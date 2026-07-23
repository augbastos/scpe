// Package scpe implements the SCPE scpe/0.1 verification algorithm (SPEC.md §8)
// as a straight, stdlib-only Go port of reference/standalone/verify_envelope.py.
//
// It is a line-by-line mirror of the Python reference verifier: same fixed
// provider registry, same safe-subject rule, same fetch-or-read-keys
// precedence, same subject.type dispatch, same status strings. The only
// external process invoked is `ssh-keygen -Y verify` (OpenSSH >= 8.2), same as
// the Python reference. No third-party Go packages are used (see go.mod: no
// requires).
//
// Statuses (SPEC §8): unattested, unsupported-version, unsupported-provider,
// unsupported-subject, identity-unverifiable, signature-invalid, tampered,
// verified.
package scpe

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	specMajor = "scpe/0"   // known MAJOR; scpe/0.x verifies, anything else does not
	namespace = "scpe/0.1" // SSHSIG namespace (SPEC §7)

	maxManifestBytes = 1 << 20  // 1 MiB defensive cap (THREAT_MODEL §3)
	maxMemberBytes   = 64 << 20 // 64 MiB cap on sig/diff/artifact members (decompression-bomb defense)
	maxKeysBytes     = 1 << 20  // 1 MiB defensive cap on a fetched .keys body
)

// IMPLEMENTED_SUBJECT_TYPES (SPEC §6): `code-change` (diff integrity) and
// `artifact` (digest of the enclosed bytes, standalone). Any other type is
// unknown; the integrity step (§8 step 7) dispatches on subject.type and fails
// CLOSED (unsupported-subject) for anything not one of these two.
var implementedSubjectTypes = map[string]bool{
	"code-change": true,
	"artifact":    true,
}

// agent-trace payload formats (SPEC §5.2). An unknown format is surfaced as
// present-unverified, never an error.
var registeredTraceFormats = map[string]bool{
	"agent-trace/1": true,
	"git-ai/notes":  true,
	"generic/1":     true,
}

// providerHost is one entry in the fixed provider registry (SPEC §8 / §11.1).
// known=false means the provider is absent from the registry (unknown, or
// reserved-but-not-yet-implemented such as `oidc`) -> unsupported-provider.
// known=true, host=="" is the `local` provider: no network fetch, keys come
// from the owner-supplied file only.
type providerHost struct {
	known bool
	host  string
}

// The fixed provider registry (SPEC §8/§11.1). This table -- and nothing in
// the manifest -- decides which host is contacted for keys.
var providerHosts = map[string]providerHost{
	"github":   {true, "github.com"},
	"gitlab":   {true, "gitlab.com"},
	"codeberg": {true, "codeberg.org"},
	"local":    {true, ""},
}

// Safe-subject rule (SPEC §8): one predictable path segment, no traversal.
var safeSubjectRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var attestationRE = regexp.MustCompile(`(?s)<!--\s*SCPE-ATTESTATION-v1\s*\n(.*?)\n\s*-->`)

// Result is the outcome of Verify: a status string (SPEC §8), free-text
// detail, the per-attestation summary (SPEC §5.3/§8 step 8), and the advisory
// `profile` label (SPEC §13), surfaced but never dispatched.
type Result struct {
	Status       string
	Detail       string
	Attestations []AttEntry
	Profile      *string // nil == unstamped
}

// AttEntry mirrors the Python {"type": ..., "status": ...} per-entry summary.
// Type is interface{} because an untrusted manifest's attestations[].type may
// be any JSON value (missing, null, non-string) — the Python reference passes
// whatever `att.get("type")` returns straight through.
type AttEntry struct {
	Type   interface{} `json:"type"`
	Status string      `json:"status"`
}

func res(status, detail string, profile *string) Result {
	return Result{Status: status, Detail: detail, Attestations: []AttEntry{}, Profile: profile}
}

// ---------------------------------------------------------------- locate (§8.1)

// loadedInput holds everything load_input can produce: the manifest and
// signature bytes (always required), and three optional payloads.
type loadedInput struct {
	manifest []byte
	sig      []byte
	diff     []byte // nil if absent
	artifact []byte // nil if absent
	keys     []byte // nil if absent
}

// loadInput accepts a vector directory, an envelope zip, or a text file
// holding an SCPE-ATTESTATION-v1 block (SPEC §9), matching the Python
// reference's load_input. A directory additionally supplies a `keys` file
// (test-vector convention, spec/test-vectors/README.md) that substitutes for
// the network fetch of §8 step 4.
func loadInput(path string) (loadedInput, error) {
	info, err := os.Stat(path)
	if err != nil {
		return loadedInput{}, fmt.Errorf("no SCPE attestation found in input: %w", err)
	}
	if info.IsDir() {
		man, errMan := readFileCapped(filepath.Join(path, "manifest.json"), maxManifestBytes)
		sig, errSig := readFileCapped(filepath.Join(path, "manifest.sig"), maxMemberBytes)
		if errMan != nil || errSig != nil {
			// A missing manifest/sig maps to unattested; an oversize one is a defensive reject.
			if os.IsNotExist(errMan) || os.IsNotExist(errSig) {
				return loadedInput{}, errors.New("no manifest.json/manifest.sig in directory")
			}
			if errMan != nil {
				return loadedInput{}, errMan
			}
			return loadedInput{}, errSig
		}
		out := loadedInput{manifest: man, sig: sig}
		if b, err := readFileCapped(filepath.Join(path, "diff.patch"), maxMemberBytes); err == nil {
			out.diff = b
		} else if !os.IsNotExist(err) {
			return loadedInput{}, err
		}
		if b, err := readFileCapped(filepath.Join(path, "artifact.bin"), maxMemberBytes); err == nil {
			out.artifact = b
		} else if !os.IsNotExist(err) {
			return loadedInput{}, err
		}
		if b, err := readFileCapped(filepath.Join(path, "keys"), maxKeysBytes); err == nil {
			out.keys = b
		} else if !os.IsNotExist(err) {
			return loadedInput{}, err
		}
		return out, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return loadedInput{}, fmt.Errorf("no SCPE attestation found in input: %w", err)
	}
	if len(raw) >= 2 && raw[0] == 'P' && raw[1] == 'K' { // envelope zip
		return fromZip(raw)
	}
	m := attestationRE.FindSubmatch(raw)
	if m != nil { // attestation embedded in a body (e.g. saved PR body)
		b64 := bytes.TrimSpace(m[1])
		blob, decErr := base64.StdEncoding.DecodeString(string(b64))
		if decErr != nil {
			return loadedInput{}, fmt.Errorf("invalid base64 attestation payload: %w", decErr)
		}
		if len(blob) < 2 || blob[0] != 'P' || blob[1] != 'K' {
			return loadedInput{}, errors.New("attestation payload is not a zip")
		}
		return fromZip(blob)
	}
	return loadedInput{}, errors.New("no SCPE attestation found in input")
}

func fromZip(blob []byte) (loadedInput, error) {
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		return loadedInput{}, fmt.Errorf("unreadable input: %w", err)
	}
	allowed := map[string]bool{
		"manifest.json": true, "manifest.sig": true,
		"diff.patch": true, "artifact.bin": true,
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		if !allowed[f.Name] {
			return loadedInput{}, fmt.Errorf("unexpected zip members: %s", f.Name)
		}
		files[f.Name] = f
	}
	if files["manifest.json"] == nil || files["manifest.sig"] == nil {
		return loadedInput{}, errors.New("unexpected zip members: missing manifest.json/manifest.sig")
	}
	man, err := readZipMember(files["manifest.json"], maxManifestBytes)
	if err != nil {
		return loadedInput{}, err
	}
	sig, err := readZipMember(files["manifest.sig"], maxMemberBytes)
	if err != nil {
		return loadedInput{}, err
	}
	out := loadedInput{manifest: man, sig: sig}
	if f := files["diff.patch"]; f != nil {
		if out.diff, err = readZipMember(f, maxMemberBytes); err != nil {
			return loadedInput{}, err
		}
	}
	if f := files["artifact.bin"]; f != nil {
		if out.artifact, err = readZipMember(f, maxMemberBytes); err != nil {
			return loadedInput{}, err
		}
	}
	return out, nil
}

// readZipMember reads a zip member, bounding the DECOMPRESSED size to `limit` bytes: the
// declared uncompressed size is checked first (rejects a bomb before allocating), then the
// actual read is limited to limit+1 so a lying header cannot exceed the cap either
// (decompression-bomb defense, THREAT_MODEL §3).
func readZipMember(f *zip.File, limit uint64) ([]byte, error) {
	if f.UncompressedSize64 > limit {
		return nil, fmt.Errorf("%s exceeds size cap", f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf := new(bytes.Buffer)
	n, err := buf.ReadFrom(io.LimitReader(rc, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if uint64(n) > limit {
		return nil, fmt.Errorf("%s exceeds size cap", f.Name)
	}
	return buf.Bytes(), nil
}

// readFileCapped reads a file, rejecting it if it exceeds `limit` bytes (directory-input
// DoS cap, THREAT_MODEL §3). The size is checked before the read.
func readFileCapped(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds size cap", filepath.Base(path))
	}
	return os.ReadFile(path)
}

// ----------------------------------------------------------------- parse (§8.2)

func parseManifest(manifestBytes []byte) (map[string]interface{}, error) {
	// Mirror Python's json.loads + isinstance(dict) strictness exactly.
	// Go's json.Decoder differs from Python's json.loads in two ways that would
	// otherwise diverge the status: (1) unmarshalling JSON `null` into a map is a
	// no-op that returns a nil error (Python raises on non-dict), and (2)
	// Decoder.Decode reads only the first JSON value and ignores trailing bytes
	// (Python's json.loads rejects trailing non-whitespace). Both are reproduced
	// here so a malformed manifest maps to signature-invalid, as the reference does.
	dec := json.NewDecoder(bytes.NewReader(manifestBytes))
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	// Reject trailing data after the single JSON value; trailing whitespace is
	// fine (json.loads strips it), so anything other than EOF here is an error.
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing data after JSON manifest")
		}
		return nil, err
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, errors.New("manifest is not a JSON object")
	}
	return m, nil
}

func versionSupported(m map[string]interface{}) bool {
	v, ok := m["spec_version"].(string)
	if !ok {
		return false
	}
	return v == specMajor || strings.HasPrefix(v, specMajor+".")
}

// ------------------------------------------------------- resolve identity (§8.3)

// subjectOK is the safe-subject rule (SPEC §8): full charset match AND no `..`
// substring. Bars `/`, whitespace, `@`, `:`, and path traversal.
func subjectOK(subject string) bool {
	return safeSubjectRE.MatchString(subject) && !strings.Contains(subject, "..")
}

// ------------------------------------------------------------ fetch keys (§8.4)

// fetchKeys fetches https://<host>/<subject>.keys -- HTTPS only, TLS
// validated (Go's http.Client validates certs/hostnames by default), no
// redirects followed. `host` comes solely from the fixed provider registry;
// `subject` is already charset-validated by subjectOK.
func fetchKeys(host, subject string) ([]byte, error) {
	seg := url.PathEscape(subject)
	target := "https://" + host + "/" + seg + ".keys"
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("redirect to %q refused (SSRF-safe fetch: no cross-host redirects)", req.URL)
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{}, // default: cert + hostname verification ON
		},
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "scpe-verify")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.Request.URL.Scheme != "https" || resp.Request.URL.Hostname() != host {
		return nil, fmt.Errorf("fetch reached unexpected URL %q", resp.Request.URL)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch failed: HTTP %d", resp.StatusCode)
	}
	limited := make([]byte, maxKeysBytes)
	n := 0
	for n < len(limited) {
		r, rerr := resp.Body.Read(limited[n:])
		n += r
		if rerr != nil {
			break
		}
	}
	return limited[:n], nil
}

// --------------------------------------------- allowed signers + SSHSIG (§8.5-6)

// verifySignature shells out to `ssh-keygen -Y verify`, exactly as the Python
// reference does, building a one-line-per-key allowed_signers file with
// principal = subject.
func verifySignature(manifestBytes, sigBytes []byte, subject string, keysBytes []byte) bool {
	var keyLines []string
	for _, ln := range strings.Split(string(keysBytes), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			keyLines = append(keyLines, ln)
		}
	}
	if len(keyLines) == 0 {
		return false
	}
	var signers strings.Builder
	for _, ln := range keyLines {
		fmt.Fprintf(&signers, "%s namespaces=%q %s\n", subject, namespace, ln)
	}

	td, err := os.MkdirTemp("", "scpe-verify-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(td)

	allowedSignersPath := filepath.Join(td, "allowed_signers")
	sigPath := filepath.Join(td, "manifest.sig")
	if err := os.WriteFile(allowedSignersPath, []byte(signers.String()), 0o600); err != nil {
		return false
	}
	if err := os.WriteFile(sigPath, sigBytes, 0o600); err != nil {
		return false
	}

	cmd := exec.Command("ssh-keygen", "-Y", "verify",
		"-f", allowedSignersPath,
		"-I", subject, "-n", namespace,
		"-s", sigPath)
	cmd.Stdin = bytes.NewReader(manifestBytes)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	return err == nil
}

// ------------------------------------------------------------- integrity (§8.7)

// normalizeDiff mirrors SPEC §6: UTF-8, CRLF/CR -> LF, exactly one trailing
// newline. diff.patch is specified to be UTF-8 with LF endings already, so a
// byte-level CRLF/CR normalization (skipping a decode/replace round-trip
// through invalid-UTF-8 handling) is equivalent for all well-formed inputs.
func normalizeDiff(raw []byte) []byte {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.TrimRight(text, "\n") + "\n"
	return []byte(text)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// codeChangeIntegrityOK: SPEC §6 -- the SHA-256 of the normalized diff MUST
// equal subject.change.diff_sha256.
func codeChangeIntegrityOK(subject map[string]interface{}, diffBytes []byte) bool {
	change, _ := subject["change"].(map[string]interface{})
	want, _ := change["diff_sha256"].(string)
	if want == "" {
		return false
	}
	return sha256Hex(normalizeDiff(diffBytes)) == want
}

// artifactIntegrityOK: SPEC §6.2 -- the SHA-256 of the RAW enclosed artifact
// bytes MUST equal subject.digest.sha256. No normalization.
func artifactIntegrityOK(subject map[string]interface{}, artifactBytes []byte) bool {
	digest, _ := subject["digest"].(map[string]interface{})
	want, _ := digest["sha256"].(string)
	if want == "" {
		return false
	}
	return sha256Hex(artifactBytes) == want
}

// ---------------------------------------------------- attestation status (§8 step 8)

func oneAttestationStatus(att interface{}) string {
	m, ok := att.(map[string]interface{})
	if !ok {
		return "present-unverified"
	}
	atype, _ := m["type"].(string)
	format, _ := m["format"].(string)
	if atype == "agent-trace" && registeredTraceFormats[format] {
		return "present-" + format
	}
	return "present-unverified"
}

// attestationsSummary: the per-attestation [{type, status}] summary (SPEC §8
// step 8). An absent or empty `attestations` list yields []; a non-list is
// treated as no attestations.
func attestationsSummary(m map[string]interface{}) []AttEntry {
	atts, ok := m["attestations"].([]interface{})
	if !ok {
		return []AttEntry{}
	}
	out := make([]AttEntry, 0, len(atts))
	for _, att := range atts {
		var atype interface{}
		if am, ok := att.(map[string]interface{}); ok {
			atype = am["type"]
		}
		out = append(out, AttEntry{Type: atype, Status: oneAttestationStatus(att)})
	}
	return out
}

// ------------------------------------------------------------------ verify (§8)

// Options carries the CLI overrides that substitute for what would otherwise
// be enclosed in the envelope or fetched over the network -- exactly the
// Python reference's --keys / --diff / --artifact.
type Options struct {
	KeysFile     string // "" == none
	DiffFile     string // "" == none
	ArtifactFile string // "" == none
}

// Verify runs SPEC.md §8 against the given path (a vector directory, an
// envelope zip, or a saved attestation body) and returns the same status
// strings as the Python reference verifier.
func Verify(path string, opts Options) Result {
	// 1. locate
	in, err := loadInput(path)
	if err != nil {
		return res("unattested", err.Error(), nil)
	}

	// 2. parse + version
	m, err := parseManifest(in.manifest)
	if err != nil {
		return res("signature-invalid", fmt.Sprintf("manifest unparsable: %v", err), nil)
	}

	// The advisory `profile` label (SPEC §13) is surfaced verbatim on every
	// post-parse outcome but never dispatched.
	var profile *string
	if p, ok := m["profile"].(string); ok {
		profile = &p
	}
	R := func(status, detail string, attestations []AttEntry) Result {
		r := res(status, detail, profile)
		if attestations != nil {
			r.Attestations = attestations
		}
		return r
	}

	if !versionSupported(m) {
		return R("unsupported-version", fmt.Sprintf("spec_version %v", m["spec_version"]), nil)
	}

	// 3. resolve the provider (§8 step 3).
	contributor, _ := m["contributor"].(map[string]interface{})
	var identity map[string]interface{}
	if contributor != nil {
		identity, _ = contributor["identity"].(map[string]interface{})
	}
	var provider, subject string
	var providerOK, subjectPresent bool
	if identity != nil {
		provider, providerOK = identity["provider"].(string)
		subject, subjectPresent = identity["subject"].(string)
	}
	ph, known := providerHosts[provider]
	if !providerOK || !known {
		return R("unsupported-provider", fmt.Sprintf("provider %q is not in the fixed registry", provider), nil)
	}
	if !subjectPresent || !subjectOK(subject) {
		return R("identity-unverifiable", "missing or malformed subject", nil)
	}
	host := ph.host // "" for the `local` provider

	// 4. keys -- --keys flag > keys file shipped beside the manifest > network.
	keysBytes := in.keys
	if opts.KeysFile != "" {
		b, err := os.ReadFile(opts.KeysFile)
		if err != nil {
			return R("identity-unverifiable", fmt.Sprintf("cannot read --keys file: %v", err), nil)
		}
		keysBytes = b
	}
	if keysBytes == nil {
		if host == "" {
			return R("identity-unverifiable", "local provider requires an owner-supplied keys file", nil)
		}
		b, err := fetchKeys(host, subject)
		if err != nil {
			return R("identity-unverifiable", fmt.Sprintf("key fetch failed: %v", err), nil)
		}
		keysBytes = b
	}
	if len(bytes.TrimSpace(keysBytes)) == 0 {
		return R("identity-unverifiable", "no published keys", nil)
	}

	// 5-6. allowed signers + SSHSIG
	if !verifySignature(in.manifest, in.sig, subject, keysBytes) {
		return R("signature-invalid", "SSHSIG verification failed", nil)
	}

	// 7. subject integrity -- dispatch on the SIGNED subject.type (SPEC §6).
	subjectBlock, _ := m["subject"].(map[string]interface{})
	var stype string
	if subjectBlock != nil {
		stype, _ = subjectBlock["type"].(string)
	}
	_ = implementedSubjectTypes // documents intent; dispatch below is explicit per SPEC §6.3
	switch stype {
	case "code-change":
		diffBytes := in.diff
		if opts.DiffFile != "" {
			b, err := os.ReadFile(opts.DiffFile)
			if err != nil {
				return R("tampered", fmt.Sprintf("cannot read --diff file: %v", err), nil)
			}
			diffBytes = b
		}
		if diffBytes == nil {
			return R("tampered", "no diff available to check integrity against", nil)
		}
		if !codeChangeIntegrityOK(subjectBlock, diffBytes) {
			return R("tampered", "diff sha256 does not match subject.change.diff_sha256", nil)
		}
	case "artifact":
		artifactBytes := in.artifact
		if opts.ArtifactFile != "" {
			b, err := os.ReadFile(opts.ArtifactFile)
			if err != nil {
				return R("tampered", fmt.Sprintf("cannot read --artifact file: %v", err), nil)
			}
			artifactBytes = b
		}
		if artifactBytes == nil {
			return R("tampered", "no artifact payload to check integrity against", nil)
		}
		if !artifactIntegrityOK(subjectBlock, artifactBytes) {
			return R("tampered", "artifact sha256 does not match subject.digest.sha256", nil)
		}
	default:
		return R("unsupported-subject", fmt.Sprintf("subject type %q is not implemented in scpe/0.1", stype), nil)
	}

	// 8. verified -- with the per-attestation {type, status} summary.
	return R("verified", "", attestationsSummary(m))
}
