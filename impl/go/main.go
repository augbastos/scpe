// Command scpe-verify is a second implementation of the SCPE `scpe/1` verifier.
//
// It exists to test the SPECIFICATION, not to serve users. The Python reference and this
// program must return identical statuses, exit codes and facets for every vector in
// spec/test-vectors-v1. Where they disagree, the specification is ambiguous and the
// specification is what gets fixed.
//
// Written from spec/SPECIFICATION.md. Cryptography is delegated to `ssh-keygen` exactly as
// the reference does, because the spec registers SSHSIG suites rather than defining
// primitives — so this is a genuine second reading of the rules, not a second crypto stack.
//
// The interesting part is §4.7. Go's encoding/json silently resolves a duplicate object key
// to last-wins, which the spec forbids: identical bytes must yield identical verdicts
// everywhere. Satisfying that rule takes real code here (see decodeNoDuplicates), and the
// fact that it takes real code in every language is the reason the rule is written down.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	specVersion   = "1"

	// SPEC 2.1. This port implements the Core profile: it does not resolve chains,
	// validate observer statements, or support anchors beyond `policy`. It therefore
	// reports `lineage: declared`, `time: unanchored` and `attribution: self-asserted`
	// and refuses what it does not implement rather than skipping it.
	profile = "core"
	statementType = "https://in-toto.io/Statement/v1"
	payloadType   = "application/vnd.in-toto+json"
)

var predicateTypes = map[string]bool{
	"https://augbastos.github.io/scpe/generation/v1": true,
}

// Suites this verifier will attempt, checked BEFORE any signature material is handed to a
// backend (§8.1). ml-dsa-44 is registered in the spec and deliberately absent: it must fail
// closed today and must not require a format change tomorrow.
var suiteAllowlist = map[string]bool{
	"sshsig-ssh-ed25519":          true,
	"sshsig-ecdsa-sha2-nistp256":  true,
}

// §8.3. The namespace a signature verifies under IS its role. The payload's claimed role
// never selects the namespace, or the record would steer the verifier.
var roleNamespaces = map[string]string{
	"producer":      "scpe/1",
	"observer":      "scpe-obs/1",
	"countersigner": "scpe-cs/1",
}

var digestAlgs = map[string]func() hash.Hash{
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

var relationships = map[string]bool{"parentOf": true, "componentOf": true, "inputTo": true}
var roles = map[string]bool{"producer": true, "observer": true, "countersigner": true}
var oversight = map[string]bool{
	"fully_autonomous": true, "prompt_guided": true, "human_validated": true,
}

// §13.3 limits. Counts drive work: signatures spawn subprocesses, edges drive traversal.
const (
	maxSidecarBytes = 4 << 20
	maxLineBytes    = 1 << 20
	maxBundleLines  = 64
	maxSignatures   = 8
	maxSigners      = 8
	maxSubjects     = 64
	maxEdges        = 64
)

// §11.5. One table, so a status can never exist without an exit code or drift from one.
var exitCodes = map[string]int{
	"ok": 0, "ok-self-anchored": 10, "subject-unavailable": 11,
	"signature-invalid": 20, "digest-mismatch": 21, "assurance-overclaimed": 22,
	"unsupported-predicate": 30, "unsupported-version": 31, "unsupported-suite": 32,
	"unsupported-digest": 33, "malformed-input": 34, "malformed-predicate": 35,
	"no-provenance-found": 40, "tooling-error": 50,
}

var attributionGloss = map[string]string{
	"self-asserted":     "the producer signed a claim about itself; nothing independent corroborates it",
	"countersigned":     "a second key signed; this does NOT establish a second party",
	"provider-attested": "a provider receipt binds bytes to an endpoint, not to weights",
	"tee-attested":      "a TEE receipt attests an enclave, not a model",
}

// refusal carries the status a fail-closed path maps to (§9.7).
type refusal struct {
	status string
	detail string
}

func (r refusal) Error() string { return r.detail }

func refuse(status, detail string) error { return refusal{status, detail} }

// ---------------------------------------------------------------- JSON hygiene (§4.7)

// decodeNoDuplicates walks the token stream and REFUSES a repeated key at any nesting
// depth, rather than resolving it.
//
// This is the clause that a standard library will not give you. encoding/json takes the
// last value silently, so a record carrying "digitalSourceType" twice would be accepted
// here and reported with whichever origin the signer put last — while a conforming verifier
// refuses it. Identical bytes, valid signature, two different answers. That is precisely
// what §4.7 exists to prevent, and satisfying it costs this function.
func decodeNoDuplicates(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	// Trailing content is not a document.
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("top-level value is not an object")
	}
	return obj, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return parseFrom(dec, tok)
}

func parseFrom(dec *json.Decoder, tok json.Token) (any, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, dup := obj[key]; dup {
					return nil, fmt.Errorf("duplicate JSON key: %q", key)
				}
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %v", t)
	default:
		return tok, nil
	}
}

// b64 accepts standard or URL-safe base64 and nothing else (RFC 4648, per DSSE).
func b64(v any, what string) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, refuse("malformed-input", what+" is not a string")
	}
	if out, err := base64.StdEncoding.DecodeString(s); err == nil {
		return out, nil
	}
	if out, err := base64.URLEncoding.DecodeString(s); err == nil {
		return out, nil
	}
	return nil, refuse("malformed-input", what+" is not valid base64")
}

// ---------------------------------------------------------------- DSSE (§4.1, §4.2)

// pae is DSSE Pre-Authentication Encoding:
//
//	PAE(t, b) = "DSSEv1" SP LEN(t) SP t SP LEN(b) SP b
//
// Length-prefixing is what removes the canonicalization problem: nothing is normalized and
// nothing is parsed before the signature is checked.
func pae(payloadTypeStr string, body []byte) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "DSSEv1 %d %s %d ", len(payloadTypeStr), payloadTypeStr, len(body))
	buf.Write(body)
	return buf.Bytes()
}

type envelope struct {
	payloadType string
	signatures  []any
	body        []byte // decoded ONCE; never re-derived from the envelope JSON (§9 step 5)
}

func parseEnvelope(raw []byte) (*envelope, error) {
	obj, err := decodeNoDuplicates(raw)
	if err != nil {
		return nil, refuse("malformed-input", err.Error())
	}
	for _, k := range []string{"payload", "payloadType", "signatures"} {
		if _, ok := obj[k]; !ok {
			return nil, refuse("malformed-input", "envelope missing "+k)
		}
	}
	pt, _ := obj["payloadType"].(string)
	if pt != payloadType {
		return nil, refuse("unsupported-payload",
			fmt.Sprintf("payloadType is %q, expected %q", pt, payloadType))
	}
	sigs, ok := obj["signatures"].([]any)
	if !ok || len(sigs) == 0 {
		return nil, refuse("malformed-input", "signatures must be a non-empty array")
	}
	if len(sigs) > maxSignatures {
		return nil, refuse("malformed-input",
			fmt.Sprintf("more than %d signatures; each one costs a subprocess", maxSignatures))
	}
	body, err := b64(obj["payload"], "payload")
	if err != nil {
		return nil, err
	}
	return &envelope{payloadType: pt, signatures: sigs, body: body}, nil
}

// ---------------------------------------------------------------- ssh-keygen backend

type sigCheck struct {
	index       int
	declared    bool
	verified    bool
	principal   string
	fingerprint string
	role        string // DISCOVERED from the namespace, never read from the payload
	errText     string
}

func sshKeygen() (string, error) {
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		// A missing backend is not a failed check. Saying signature-invalid here would
		// assert that a verification ran and rejected the signature, which is false (§11.5).
		return "", refuse("tooling-error", "ssh-keygen not found on PATH")
	}
	return p, nil
}

// sshsigVerify checks one signature under one namespace.
//
// Two steps, per §8.3: `-Y find-principals` answers "who in this policy holds the key that
// made this signature" and does NOT enforce the namespace; `-Y verify -n` enforces both.
// The principal is read out of the operator's own policy file, so no attacker-controlled
// string is ever interpolated into a policy line.
func sshsigVerify(signed, signature []byte, policy, namespace string) (bool, string, string) {
	exe, err := sshKeygen()
	if err != nil {
		return false, "", err.Error()
	}
	tmp, err := os.MkdirTemp("", "scpe-go-")
	if err != nil {
		return false, "", err.Error()
	}
	defer os.RemoveAll(tmp)
	sigPath := filepath.Join(tmp, "sig")
	if err := os.WriteFile(sigPath, signature, 0o600); err != nil {
		return false, "", err.Error()
	}

	find := exec.Command(exe, "-Y", "find-principals", "-s", sigPath, "-f", policy)
	find.Stdin = bytes.NewReader(signed)
	out, _ := find.Output()
	var principals []string
	for _, ln := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(ln); s != "" {
			principals = append(principals, s)
		}
	}
	if len(principals) == 0 {
		return false, "", "no principal in the policy holds this key"
	}

	last := ""
	for _, p := range principals {
		cmd := exec.Command(exe, "-Y", "verify", "-s", sigPath, "-f", policy,
			"-I", p, "-n", namespace)
		cmd.Stdin = bytes.NewReader(signed)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			return true, p, ""
		}
		last = strings.TrimSpace(stderr.String())
	}
	if last == "" {
		last = "signature did not verify"
	}
	return false, principals[0], last
}

// verifyBlind verifies every signature BEFORE the payload is parsed.
//
// The role is discovered, not read: each signature is tried under every registered
// namespace and the one it verifies under is its role. A record claiming observer while
// carrying a producer-namespace signature therefore does not verify as an observation, and
// no attacker-controlled field selects which namespace runs.
func verifyBlind(env *envelope, policy string) ([]sigCheck, error) {
	signed := pae(env.payloadType, env.body)
	var checks []sigCheck

	// Deterministic order so two runs cannot differ.
	orderedRoles := make([]string, 0, len(roleNamespaces))
	for r := range roleNamespaces {
		orderedRoles = append(orderedRoles, r)
	}
	sort.Strings(orderedRoles)

	for i, entry := range env.signatures {
		m, ok := entry.(map[string]any)
		if !ok {
			return nil, refuse("malformed-input", fmt.Sprintf("signatures[%d] is not an object", i))
		}
		rawSig, err := b64(m["sig"], fmt.Sprintf("signatures[%d].sig", i))
		if err != nil {
			return nil, err
		}
		out := sigCheck{index: i, errText: "no registered namespace verified this signature"}
		for _, role := range orderedRoles {
			ok, principal, errText := sshsigVerify(signed, rawSig, policy, roleNamespaces[role])
			if ok {
				out = sigCheck{index: i, verified: true, principal: principal, role: role}
				break
			}
			if errText != "" && !strings.Contains(errText, "namespace does not match") {
				out.errText = errText
			}
		}
		checks = append(checks, out)
	}
	return checks, nil
}

// ---------------------------------------------------------------- statement (§4.3, §5)

type statement struct {
	subject   []any
	predicate map[string]any
}

func parseStatement(body []byte) (*statement, error) {
	obj, err := decodeNoDuplicates(body)
	if err != nil {
		return nil, refuse("malformed-input", err.Error())
	}
	if t, _ := obj["_type"].(string); t != statementType {
		return nil, refuse("malformed-input", fmt.Sprintf("_type is %q", t))
	}
	pt, _ := obj["predicateType"].(string)
	if !predicateTypes[pt] {
		return nil, refuse("unsupported-predicate", "unrecognised predicateType: "+pt)
	}
	subject, ok := obj["subject"].([]any)
	if !ok || len(subject) == 0 {
		return nil, refuse("malformed-input", "subject must be a non-empty array")
	}
	if len(subject) > maxSubjects {
		return nil, refuse("malformed-input", "too many subjects")
	}
	for _, el := range subject {
		m, ok := el.(map[string]any)
		if !ok {
			return nil, refuse("malformed-input", "subject element is not an object")
		}
		if _, ok := m["digest"].(map[string]any); !ok {
			return nil, refuse("malformed-input", "every subject element requires a digest object")
		}
	}
	pred, ok := obj["predicate"].(map[string]any)
	if !ok {
		return nil, refuse("malformed-predicate", "predicate must be an object")
	}
	if v, _ := pred["scpeVersion"].(string); v != specVersion {
		return nil, refuse("unsupported-version",
			fmt.Sprintf("scpeVersion %q; this verifier implements %q", v, specVersion))
	}
	return &statement{subject: subject, predicate: pred}, nil
}

func validatePredicate(pred map[string]any) ([]map[string]any, error) {
	gen, ok := pred["generation"].(map[string]any)
	if !ok {
		return nil, refuse("malformed-predicate", "generation is required and must be an object")
	}
	if s, ok := gen["digitalSourceType"].(string); !ok || s == "" {
		return nil, refuse("malformed-predicate", "generation.digitalSourceType is required")
	}
	if v, present := gen["humanOversight"]; present {
		s, _ := v.(string)
		if !oversight[s] {
			return nil, refuse("malformed-predicate", "humanOversight is not a C2PA value")
		}
	}

	rawSigners, ok := pred["signer"].([]any)
	if !ok || len(rawSigners) == 0 {
		return nil, refuse("malformed-predicate", "signer must be a non-empty array")
	}
	if len(rawSigners) > maxSigners {
		return nil, refuse("malformed-predicate", "too many signer entries")
	}
	var signers []map[string]any
	for _, e := range rawSigners {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, refuse("malformed-predicate", "signer entries must be objects")
		}
		for _, req := range []string{"keyFingerprint", "alg", "role"} {
			if s, ok := m[req].(string); !ok || s == "" {
				return nil, refuse("malformed-predicate", "signer[]."+req+" is required")
			}
		}
		if !roles[m["role"].(string)] {
			return nil, refuse("malformed-predicate", "unknown signer role")
		}
		// Checked BEFORE verification is attempted (§8.1, RFC 8725 §3.1).
		if !suiteAllowlist[m["alg"].(string)] {
			return nil, refuse("unsupported-suite",
				fmt.Sprintf("suite %q is not on the allowlist", m["alg"]))
		}
		signers = append(signers, m)
	}

	edges, _ := pred["derivedFrom"].([]any)
	if len(edges) > maxEdges {
		return nil, refuse("malformed-predicate", "too many derivedFrom edges")
	}
	parents := 0
	for _, e := range edges {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, refuse("malformed-predicate", "derivedFrom entries must be objects")
		}
		rel, _ := m["relationship"].(string)
		if !relationships[rel] {
			return nil, refuse("malformed-predicate", "relationship is not one of the three C2PA relations")
		}
		res, ok := m["resource"].(map[string]any)
		if !ok {
			return nil, refuse("malformed-predicate", "every derivedFrom edge requires a resource")
		}
		if _, ok := res["digest"].(map[string]any); !ok {
			return nil, refuse("malformed-predicate", "every derivedFrom edge requires resource.digest")
		}
		if rel == "parentOf" {
			parents++
			pin, _ := m["statementDigest"].(map[string]any)
			if s, ok := pin["sha256"].(string); !ok || s == "" {
				return nil, refuse("malformed-predicate", "a parentOf edge requires statementDigest.sha256")
			}
		}
	}
	if parents > 1 {
		return nil, refuse("malformed-predicate", "a statement may carry at most one parentOf edge")
	}

	// §8.4 narrowing 2: an observation is a separate statement and may not reach beyond
	// what an observer can witness.
	roleSet := map[string]bool{}
	for _, s := range signers {
		roleSet[s["role"].(string)] = true
	}
	if roleSet["observer"] {
		if len(roleSet) != 1 {
			return nil, refuse("malformed-predicate",
				"an observer signature may not share an envelope with another role")
		}
		obs, _ := pred["observed"].(map[string]any)
		sd, _ := obs["statementDigest"].(map[string]any)
		if s, ok := sd["sha256"].(string); !ok || s == "" {
			return nil, refuse("malformed-predicate",
				"an observer statement requires observed.statementDigest.sha256")
		}
		for _, f := range []string{"provider", "model", "humanOversight", "producedAt"} {
			if _, present := gen[f]; present {
				return nil, refuse("malformed-predicate",
					"an observer statement may not carry generation."+f)
			}
		}
		for _, f := range []string{"derivedFrom", "commitments", "run"} {
			if v, present := pred[f]; present && v != nil {
				return nil, refuse("malformed-predicate",
					"an observer statement may not carry "+f)
			}
		}
	}
	return signers, nil
}

// matchDeclared binds each verified signature to the signer[] entry that claims it (§8.2).
func matchDeclared(checks []sigCheck, signers []map[string]any) {
	byRole := map[string][]map[string]any{}
	for _, s := range signers {
		r := s["role"].(string)
		byRole[r] = append(byRole[r], s)
	}
	for i := range checks {
		if !checks[i].verified || checks[i].role == "" {
			continue
		}
		cands := byRole[checks[i].role]
		if len(cands) == 0 {
			continue // verified, but the payload claims no signer in that role
		}
		checks[i].declared = true
		checks[i].fingerprint = cands[0]["keyFingerprint"].(string)
	}
}

// ---------------------------------------------------------------- binding (§4.5, §10.2)

func digestFile(path string, algs []string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, refuse("malformed-input", "cannot read artifact")
	}
	defer f.Close()
	hs := map[string]hash.Hash{}
	var writers []io.Writer
	for _, a := range algs {
		h := digestAlgs[a]()
		hs[a] = h
		writers = append(writers, h)
	}
	if _, err := io.Copy(io.MultiWriter(writers...), f); err != nil {
		return nil, refuse("malformed-input", "cannot read artifact")
	}
	out := map[string]string{}
	for a, h := range hs {
		out[a] = fmt.Sprintf("%x", h.Sum(nil))
	}
	return out, nil
}

// bindSubject applies the AND rule. in-toto matches a DigestSet if ANY algorithm matches;
// SCPE narrows that to every recognised algorithm, because OR-matching lets an attacker
// choose the weak one when a strong one is present (§4.5).
func bindSubject(subject []any, artifact string) (string, []string, error) {
	if artifact == "" {
		return "unbound", nil, nil
	}
	for _, el := range subject {
		m := el.(map[string]any)
		declared := map[string]string{}
		for k, v := range m["digest"].(map[string]any) {
			if s, ok := v.(string); ok {
				declared[k] = s
			}
		}
		var shared []string
		for a := range declared {
			if _, known := digestAlgs[a]; known {
				shared = append(shared, a)
			}
		}
		if len(shared) == 0 {
			continue
		}
		sort.Strings(shared)
		actual, err := digestFile(artifact, shared)
		if err != nil {
			return "", nil, err
		}
		for _, a := range shared {
			if !strings.EqualFold(actual[a], declared[a]) {
				return "mismatch", nil, nil
			}
		}
		return "bound", []string{
			"subject digest matches the supplied bytes (" + strings.Join(shared, ", ") + ")",
		}, nil
	}
	return "", nil, refuse("unsupported-digest",
		"no subject digest uses an algorithm this verifier can recompute")
}

// ---------------------------------------------------------------- discovery (§7)

func findSidecar(artifact, explicit string) string {
	if explicit != "" {
		if fileExists(explicit) {
			return explicit
		}
		return ""
	}
	for _, c := range []string{artifact + ".scpe.jsonl", artifact + ".scpe"} {
		if fileExists(c) {
			return c
		}
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func readBundle(path string) ([][]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, refuse("malformed-input", "cannot stat sidecar")
	}
	if st.Size() > maxSidecarBytes { // checked BEFORE reading (§4.7)
		return nil, refuse("malformed-input", "sidecar exceeds size cap")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, refuse("malformed-input", "cannot read sidecar")
	}
	if len(raw) > maxSidecarBytes {
		return nil, refuse("malformed-input", "sidecar exceeds size cap")
	}
	var lines [][]byte
	for _, ln := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(ln)) == 0 {
			continue
		}
		if len(ln) > maxLineBytes {
			return nil, refuse("malformed-input", "bundle line exceeds size cap")
		}
		lines = append(lines, ln)
	}
	if len(lines) == 0 {
		return nil, refuse("malformed-input", "sidecar is empty")
	}
	if len(lines) > maxBundleLines {
		return nil, refuse("malformed-input", "bundle exceeds line cap")
	}
	return lines, nil
}

// ---------------------------------------------------------------- result (§11)

type result struct {
	Status               string            `json:"status"`
	Facets               map[string]string `json:"facets"`
	Proved               []string          `json:"proved"`
	Declared             []string          `json:"declared"`
	NotChecked           []string          `json:"not_checked"`
	UndeclaredSignatures int               `json:"undeclared_signatures"`
	Peers                []any             `json:"peers"`
	Detail               string            `json:"detail"`
	Exit                 int               `json:"exit"`
}

func newResult(status string) *result {
	return &result{
		Status: status, Facets: map[string]string{},
		Proved: []string{}, Declared: []string{}, NotChecked: []string{},
		Peers: []any{}, Exit: exitCodes[status],
	}
}

// collectDeclared gathers everything the signer SAID. §11.3 keeps these in exactly one
// place, under a name that says what they are, so a renderer cannot present a claim as a
// finding.
func collectDeclared(st *statement) []string {
	out := []string{}
	if gen, ok := st.predicate["generation"].(map[string]any); ok {
		for _, k := range []string{"digitalSourceType", "provider", "model", "humanOversight", "producedAt"} {
			if v, present := gen[k]; present {
				out = append(out, fmt.Sprintf("generation.%s = %v", k, v))
			}
		}
	}
	for i, el := range st.subject {
		m := el.(map[string]any)
		if n, ok := m["name"].(string); ok && n != "" {
			out = append(out, fmt.Sprintf("subject[%d].name = %s", i, n))
		}
		if mt, ok := m["mediaType"].(string); ok && mt != "" {
			out = append(out, fmt.Sprintf("subject[%d].mediaType = %s", i, mt))
		}
	}
	if edges, ok := st.predicate["derivedFrom"].([]any); ok {
		for _, e := range edges {
			m := e.(map[string]any)
			name := "<unnamed>"
			if r, ok := m["resource"].(map[string]any); ok {
				if n, ok := r["name"].(string); ok {
					name = n
				}
			}
			out = append(out, fmt.Sprintf("derivedFrom: %v %s", m["relationship"], name))
		}
	}
	return out
}

// buildNotChecked is REQUIRED and non-empty on any passing result (§11.4). The generation
// claim stays unverified at both self-asserted and countersigned: a countersignature
// attests that a record existed, never that what it says is true.
func buildNotChecked(facets map[string]string, st *statement) []string {
	out := []string{}
	gen, _ := st.predicate["generation"].(map[string]any)
	model := "the named model"
	if m, ok := gen["model"].(string); ok && m != "" {
		model = m
	}
	switch facets["attribution"] {
	case "self-asserted":
		out = append(out, "that "+model+" produced these bytes - the claim is signed by the "+
			"producer about itself, and no provider or TEE attestation is present")
	case "countersigned":
		out = append(out, "that "+model+" produced these bytes - a countersignature attests "+
			"that the record existed, not that it is true")
		out = append(out, "that a second PARTY was involved - a second key signed, and no "+
			"offline verifier can tell two keys from two people")
	}
	if facets["binding"] == "unbound" {
		out = append(out, "that any file matches this record - no artifact bytes were supplied")
	}
	if facets["time"] == "unanchored" {
		out = append(out, "when this was signed - no verified time anchor is present")
	}
	if facets["lineage"] == "declared" {
		out = append(out, "that any derivation edge occurred - no parent statement was resolved")
	}
	out = append(out, "that no other transformation occurred - SCPE cannot express that claim")
	return out
}

// ---------------------------------------------------------------- facets (§10)

func sameSubject(a, b []any) bool {
	set := map[string]bool{}
	for _, el := range a {
		if m, ok := el.(map[string]any); ok {
			if d, ok := m["digest"].(map[string]any); ok {
				for alg, v := range d {
					if s, ok := v.(string); ok {
						set[alg+":"+strings.ToLower(s)] = true
					}
				}
			}
		}
	}
	for _, el := range b {
		if m, ok := el.(map[string]any); ok {
			if d, ok := m["digest"].(map[string]any); ok {
				for alg, v := range d {
					if s, ok := v.(string); ok && set[alg+":"+strings.ToLower(s)] {
						return true
					}
				}
			}
		}
	}
	return false
}

type observation struct {
	verified       bool
	observedDigest string
	subject        []any
	keys           map[string]bool
	principals     map[string]bool
}

// attribution deliberately does NOT claim a second party. No offline verifier can tell two
// keys from two people — nothing in allowed_signers distinguishes a colleague's key from a
// second laptop key — so the facet reports the mechanical fact and the gloss says so (§10.5).
func attribution(producerPayload []byte, producerSubject []any,
	producerKeys, producerPrincipals map[string]bool,
	observations []observation, anchor string) string {

	if anchor != "policy" && anchor != "forge" {
		// A producer who supplied the key file supplied both ends of the corroboration.
		return "self-asserted"
	}
	want := fmt.Sprintf("%x", sha256.Sum256(producerPayload))
	for _, obs := range observations {
		if !obs.verified || !strings.EqualFold(obs.observedDigest, want) {
			continue
		}
		if !sameSubject(obs.subject, producerSubject) {
			continue
		}
		sharesKey := false
		for k := range obs.keys {
			if producerKeys[k] {
				sharesKey = true
			}
		}
		if sharesKey {
			continue
		}
		distinct := len(obs.principals) > 0
		for p := range obs.principals {
			if producerPrincipals[p] {
				distinct = false
			}
		}
		if distinct {
			return "countersigned"
		}
	}
	return "self-asserted"
}

// ---------------------------------------------------------------- verify (§9)

func verify(artifact, sidecarPath, policy string) *result {
	if artifact != "" && sidecarPath == "" {
		sidecarPath = findSidecar(artifact, "")
	}
	if sidecarPath == "" || !fileExists(sidecarPath) {
		r := newResult("no-provenance-found")
		r.Detail = "no .scpe.jsonl sidecar found next to the artifact"
		return r
	}

	res, err := run(artifact, sidecarPath, policy)
	if err != nil {
		var ref refusal
		if errors.As(err, &ref) {
			status := ref.status
			if _, known := exitCodes[status]; !known {
				status = "malformed-input"
			}
			r := newResult(status)
			r.Detail = ref.detail
			return r
		}
		r := newResult("malformed-input")
		r.Detail = err.Error()
		return r
	}
	return res
}

func run(artifact, sidecarPath, policy string) (*result, error) {
	lines, err := readBundle(sidecarPath)
	if err != nil {
		return nil, err
	}

	var prodEnv *envelope
	var prodStmt *statement
	var prodSigners []map[string]any
	var prodChecks []sigCheck
	type obsLine struct {
		stmt   *statement
		checks []sigCheck
	}
	var obsLines []obsLine

	for _, raw := range lines {
		env, err := parseEnvelope(raw)
		if err != nil {
			return nil, err
		}
		// VERIFY FIRST (§9 steps 4-6): the payload is not parsed until a trusted key has
		// vouched for those exact bytes.
		checks, err := verifyBlind(env, policy)
		if err != nil {
			return nil, err
		}
		anyVerified := false
		for _, c := range checks {
			if c.verified {
				anyVerified = true
			}
		}
		if !anyVerified {
			if prodEnv == nil && len(lines) == 1 {
				msg := "no signature verified"
				if len(checks) > 0 && checks[0].errText != "" {
					msg = checks[0].errText
				}
				return nil, refuse("signature-invalid", msg)
			}
			continue
		}

		st, err := parseStatement(env.body)
		if err != nil {
			return nil, err
		}
		signers, err := validatePredicate(st.predicate)
		if err != nil {
			return nil, err
		}
		matchDeclared(checks, signers)

		onlyObserver := true
		for _, c := range checks {
			if c.verified && c.role != "observer" {
				onlyObserver = false
			}
		}
		if onlyObserver {
			obsLines = append(obsLines, obsLine{st, checks})
		} else if prodEnv == nil {
			prodEnv, prodStmt, prodSigners, prodChecks = env, st, signers, checks
		} else {
			return nil, refuse("malformed-input", "bundle carries more than one producer statement")
		}
	}

	if prodEnv == nil {
		return nil, refuse("signature-invalid",
			"no producer statement in the bundle verified against the anchor")
	}

	var declaredChecks []sigCheck
	undeclared := 0
	for _, c := range prodChecks {
		if c.declared {
			declaredChecks = append(declaredChecks, c)
		} else {
			undeclared++
		}
	}
	if len(declaredChecks) == 0 {
		return nil, refuse("signature-invalid",
			"no signature was made by a key declared in signer[]")
	}
	// Every declared signature must verify (§8.4). "At least one" would let a statement
	// carrying one good and one bad signature pass by default.
	for _, c := range declaredChecks {
		if !c.verified {
			return nil, refuse("signature-invalid", "a declared signature failed: "+c.errText)
		}
	}

	binding, bindingProof, err := bindSubject(prodStmt.subject, artifact)
	if err != nil {
		return nil, err
	}
	if binding == "mismatch" {
		r := newResult("digest-mismatch")
		r.Detail = "supplied bytes do not match the signed subject digest"
		r.UndeclaredSignatures = undeclared
		return r, nil
	}

	producerKeys := map[string]bool{}
	for _, s := range prodSigners {
		producerKeys[s["keyFingerprint"].(string)] = true
	}
	producerPrincipals := map[string]bool{}
	for _, c := range declaredChecks {
		if c.principal != "" {
			producerPrincipals[c.principal] = true
		}
	}

	var observations []observation
	for _, ol := range obsLines {
		var verified []sigCheck
		for _, c := range ol.checks {
			if c.declared && c.verified {
				verified = append(verified, c)
			}
		}
		obs := observation{
			verified: len(verified) > 0, subject: ol.stmt.subject,
			keys: map[string]bool{}, principals: map[string]bool{},
		}
		if o, ok := ol.stmt.predicate["observed"].(map[string]any); ok {
			if sd, ok := o["statementDigest"].(map[string]any); ok {
				obs.observedDigest, _ = sd["sha256"].(string)
			}
		}
		for _, c := range verified {
			obs.keys[c.fingerprint] = true
			obs.principals[c.principal] = true
		}
		observations = append(observations, obs)
	}

	anchor := "policy" // this implementation supports the operator-supplied policy anchor only
	facets := map[string]string{
		"binding":   binding,
		"signature": "valid",
		"anchor":    anchor,
		"attribution": attribution(prodEnv.body, prodStmt.subject, producerKeys,
			producerPrincipals, observations, anchor),
		"time":    "unanchored",
		"lineage": lineage(prodStmt),
	}

	// §10.1: a producer may not assert a facet. The verifier recomputes and refuses.
	if asserted, ok := prodStmt.predicate["assurance"].(map[string]any); ok {
		var differing []string
		for k, v := range asserted {
			if s, ok := v.(string); ok && facets[k] != s {
				differing = append(differing, fmt.Sprintf("%s=%q", k, s))
			}
		}
		if len(differing) > 0 {
			sort.Strings(differing)
			r := newResult("assurance-overclaimed")
			r.Facets = facets
			r.UndeclaredSignatures = undeclared
			r.Detail = "producer asserted " + strings.Join(differing, ", ") +
				"; the verifier computed otherwise"
			return r, nil
		}
	}

	status := "ok"
	if binding == "unbound" {
		status = "subject-unavailable"
	}

	proved := append([]string{}, bindingProof...)
	for _, c := range declaredChecks {
		proved = append(proved, fmt.Sprintf(
			"signature over the predicate by %s (principal %s, role-scoped namespace)",
			c.fingerprint, c.principal))
	}
	if anchor == "policy" {
		proved = append(proved, "the signing key is listed in the operator's allowed_signers file")
	}

	r := newResult(status)
	r.Facets = facets
	r.Proved = proved
	r.Declared = collectDeclared(prodStmt)
	r.NotChecked = buildNotChecked(facets, prodStmt)
	r.UndeclaredSignatures = undeclared
	return r, nil
}

func lineage(st *statement) string {
	edges, _ := st.predicate["derivedFrom"].([]any)
	if len(edges) == 0 {
		return "none"
	}
	// Chain resolution is not implemented here; `declared` is the honest value, and there
	// is no `complete` value at any depth (§6.3).
	return "declared"
}

// ---------------------------------------------------------------- render

func render(r *result) string {
	var b strings.Builder
	mark := "NO"
	if r.Status == "ok" || r.Status == "ok-self-anchored" || r.Status == "subject-unavailable" {
		mark = "OK"
	}
	fmt.Fprintf(&b, "[%s] %s\n", mark, r.Status)
	if r.Detail != "" {
		fmt.Fprintf(&b, "     %s\n", r.Detail)
	}
	if len(r.Facets) > 0 {
		b.WriteString("\n  What this result is:\n")
		for _, k := range []string{"binding", "signature", "anchor", "attribution", "time", "lineage"} {
			v, ok := r.Facets[k]
			if !ok {
				continue
			}
			gloss := ""
			if k == "attribution" {
				if g, ok := attributionGloss[v]; ok {
					gloss = "  - " + g
				}
			}
			fmt.Fprintf(&b, "    %-12s %s%s\n", k, v, gloss)
		}
	}
	section := func(title string, items []string, bullet string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n  %s\n", title)
		for _, it := range items {
			fmt.Fprintf(&b, "    %s %s\n", bullet, it)
		}
	}
	section("Proved (checks this verifier performed):", r.Proved, "+")
	section("Declared by the signer (NOT verified):", r.Declared, "~")
	section("Not checked:", r.NotChecked, "?")
	return b.String()
}

func main() {
	policy := flag.String("policy", "", "an OpenSSH allowed_signers file (anchor: policy)")
	sidecar := flag.String("sidecar", "", "explicit path to the .scpe.jsonl record")
	asJSON := flag.Bool("json", false, "emit the machine-readable result shape")
	showProfile := flag.Bool("profile", false, "print the conformance profile and exit")

	// Go's flag package stops parsing at the first non-flag argument, so
	// `scpe-verify FILE --policy P` would silently ignore --policy and every vector would
	// fail for want of an anchor. The reference CLI accepts the artifact first, so the
	// positional is hoisted before parsing to keep one invocation working in both. Worth
	// recording: the specification describes a CLI shape without saying that flags may
	// follow the operand, and that is a real portability assumption.
	args := os.Args[1:]
	artifact := ""
	rest := make([]string, 0, len(args))
	for _, a := range args {
		if artifact == "" && !strings.HasPrefix(a, "-") && !isFlagValue(args, a) {
			artifact = a
			continue
		}
		rest = append(rest, a)
	}
	if err := flag.CommandLine.Parse(rest); err != nil {
		os.Exit(64)
	}
	if *showProfile {
		fmt.Println(profile)
		os.Exit(0)
	}
	if artifact == "" && flag.NArg() > 0 {
		artifact = flag.Arg(0)
	}
	if artifact == "" && *sidecar == "" {
		fmt.Fprintln(os.Stderr, "usage: scpe-verify ARTIFACT --policy allowed_signers [--json]")
		os.Exit(64)
	}
	if *policy == "" {
		r := newResult("malformed-input")
		r.Detail = "no trust anchor: pass --policy (allowed_signers)"
		emit(r, *asJSON)
		os.Exit(r.Exit)
	}

	r := verify(artifact, *sidecar, *policy)
	emit(r, *asJSON)
	os.Exit(r.Exit)
}

// isFlagValue reports whether a bare token is the VALUE of the preceding flag
// (`--policy p` style) rather than the artifact operand.
func isFlagValue(args []string, tok string) bool {
	for i, a := range args {
		if a == tok && i > 0 {
			prev := args[i-1]
			if strings.HasPrefix(prev, "-") && !strings.Contains(prev, "=") &&
				prev != "--json" && prev != "-json" {
				return true
			}
		}
	}
	return false
}

func emit(r *result, asJSON bool) {
	if asJSON {
		out, _ := json.Marshal(r)
		fmt.Println(string(out))
		return
	}
	fmt.Print(render(r))
}
