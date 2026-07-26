//! SCPE scpe/0.1 verification algorithm (SPEC.md §8).
//!
//! This is an INDEPENDENT Rust port of the same algorithm implemented by
//! `impl/go/internal/scpe/verify.go` (itself a port of
//! `reference/standalone/verify_envelope.py`, the ultimate reference). It
//! mirrors both line for line where practical: same fixed provider registry,
//! same safe-subject rule, same key precedence (--keys flag > keys file
//! beside the manifest > network fetch), same subject.type dispatch, same
//! status strings. The only external process invoked is `ssh-keygen -Y
//! verify` (OpenSSH >= 8.2), same as the Go and Python implementations.
//!
//! Two things here go beyond a literal transcription of the reference, and
//! both are mirrored in the Go and Python verifiers:
//!
//!   * a repeated JSON key anywhere in the manifest is a parse failure rather
//!     than the silent last-one-wins merge every JSON library performs, since
//!     otherwise the same signed bytes could yield two different verdicts —
//!     see `find_duplicate_key`;
//!   * the verdict names which key tier backed it, because a `keys` file that
//!     rode inside the input was chosen by the submitter, not by the forge —
//!     see [`KeySource`].
//!
//! Conformance contract for this port: the 18 normative vectors under
//! `spec/test-vectors/` (see `tests/vectors.rs`), all of which exercise the
//! directory-input path with an owner-supplied `keys` file. The envelope-zip
//! input path and the HTTPS key-fetch path are NOT exercised by the vectors;
//! this port implements the directory-input path fully and honestly stubs
//! those two paths (see `load_input` / `fetch_keys` below) rather than
//! faking them.
//!
//! Statuses (SPEC §8): unattested, unsupported-version, unsupported-provider,
//! unsupported-subject, identity-unverifiable, signature-invalid, tampered,
//! verified.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const SPEC_MAJOR: &str = "scpe/0"; // known MAJOR; scpe/0.x verifies, anything else does not
const NAMESPACE: &str = "scpe/0.1"; // SSHSIG namespace (SPEC §7)

const MAX_MANIFEST_BYTES: u64 = 1 << 20; // 1 MiB defensive cap (THREAT_MODEL §3)
const MAX_MEMBER_BYTES: u64 = 64 << 20; // 64 MiB cap on sig/diff/artifact members (DoS defense)
const MAX_KEYS_BYTES: u64 = 1 << 20; // 1 MiB defensive cap on a keys file

// agent-trace payload formats (SPEC §5.2). An unknown format is surfaced as
// present-unverified, never an error.
const REGISTERED_TRACE_FORMATS: [&str; 3] = ["agent-trace/1", "git-ai/notes", "generic/1"];

// ------------------------------------------------------------------ Result

/// AttEntry mirrors the Go/Python `{"type": ..., "status": ...}` per-entry
/// summary. `r#type` is a `serde_json::Value` because an untrusted
/// manifest's `attestations[].type` may be any JSON value (missing, null,
/// non-string) — we pass whatever the manifest carried straight through,
/// same as the Go/Python references.
#[derive(Debug, Clone, PartialEq)]
pub struct AttEntry {
    pub r#type: Value,
    pub status: String,
}

/// KeySource names which tier of the §8 step 4 precedence supplied the public
/// keys the identity check ran against.
///
/// All three tiers can end in `verified`, but they are not the same claim: a
/// `keys` file travelling inside the input is controlled by whoever submitted
/// the package, so such a package can present a `github` identity without
/// github.com ever being contacted. That tier is NOT removed — the 18
/// normative vectors all ship their own `keys` file, which is what lets the
/// conformance suite run offline — so the honest fix is to say out loud which
/// anchor was used instead of letting all three look alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// `--keys FILE`: the operator named the anchor out of band.
    Flag,
    /// A `keys` file found beside the manifest in the input — submitter-controlled.
    Bundled,
    /// Fetched from the provider's host in the fixed registry. Unreachable in
    /// THIS port as long as `fetch_keys` is the honest stub it is today: the
    /// tier is wired up so the disclosure is complete the day the fetch lands,
    /// but a Rust run can only ever report `flag`, `bundled`, or nothing.
    Forge,
}

impl KeySource {
    /// The wire spelling used by `--json` and by the human line.
    pub fn as_str(self) -> &'static str {
        match self {
            KeySource::Flag => "flag",
            KeySource::Bundled => "bundled",
            KeySource::Forge => "forge",
        }
    }
}

/// VerifyResult is the outcome of [`verify`]: a status string (SPEC §8),
/// free-text detail, the per-attestation summary (SPEC §5.3/§8 step 8), the
/// advisory `profile` label (SPEC §13), surfaced but never dispatched, and
/// the [`KeySource`] the verdict rests on.
///
/// `key_source` is `None` whenever the verdict was reached without key bytes
/// ever being in hand — every outcome upstream of §8 step 4, and step 4's own
/// three failures (unreadable `--keys`, failed fetch, `local` with no keys):
/// no key material was consulted, so no tier is claimed.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub status: String,
    pub detail: String,
    pub attestations: Vec<AttEntry>,
    pub profile: Option<String>,
    pub key_source: Option<KeySource>,
}

fn simple_result(status: &str, detail: &str) -> VerifyResult {
    VerifyResult {
        status: status.to_string(),
        detail: detail.to_string(),
        attestations: vec![],
        profile: None,
        key_source: None,
    }
}

/// `display_type` mirrors Python's `f"{a['type']}={a['status']}"` /
/// Go's `fmt.Sprintf("%v=%s", a.Type, a.Status)`: an attestation `type` that
/// is a JSON string is printed UNQUOTED. The 18 normative vectors only ever
/// carry string types ("agent-trace", "timestamp"); the other arms are a
/// best-effort, Python-`str()`-flavoured fallback for the untested cases.
pub fn display_type(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "None".to_string(),
        Value::Bool(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------- locate (§8.1)

struct LoadedInput {
    manifest: Vec<u8>,
    sig: Vec<u8>,
    diff: Option<Vec<u8>>,
    artifact: Option<Vec<u8>>,
    keys: Option<Vec<u8>>,
}

/// loadInput accepts a vector directory (fully implemented) or an envelope
/// zip / saved-attestation-body file (honestly stubbed — see module doc).
/// A directory additionally supplies a `keys` file (test-vector convention,
/// spec/test-vectors/README.md) that substitutes for the network fetch of
/// §8 step 4.
fn load_input(path: &Path) -> Result<LoadedInput, String> {
    let metadata =
        fs::metadata(path).map_err(|e| format!("no SCPE attestation found in input: {e}"))?;

    if metadata.is_dir() {
        let man = read_file_capped(path.join("manifest.json"), MAX_MANIFEST_BYTES);
        let sig = read_file_capped(path.join("manifest.sig"), MAX_MEMBER_BYTES);
        let (manifest, sig) = match (man, sig) {
            (Ok(m), Ok(s)) => (m, s),
            // Missing OR oversized manifest/sig -> unattested (fail-closed on the DoS cap too).
            _ => return Err("no manifest.json/manifest.sig in directory".to_string()),
        };
        let diff = read_optional_capped(path.join("diff.patch"), MAX_MEMBER_BYTES)?;
        let artifact = read_optional_capped(path.join("artifact.bin"), MAX_MEMBER_BYTES)?;
        let keys = read_optional_capped(path.join("keys"), MAX_KEYS_BYTES)?;
        return Ok(LoadedInput {
            manifest,
            sig,
            diff,
            artifact,
            keys,
        });
    }

    // Non-directory input: an envelope zip, or a text file holding an
    // SCPE-ATTESTATION-v1 block (e.g. a saved PR body). Neither path is
    // exercised by the 18 normative vectors (all 18 are directories), so
    // this port stubs both with an honest error rather than faking support.
    Err("envelope zip / attestation-in-body input not implemented in the Rust port yet; \
         supply a vector directory (manifest.json + manifest.sig [+ diff.patch/artifact.bin/keys])"
        .to_string())
}

/// Read a file, rejecting it if it exceeds `limit` bytes (directory-input DoS cap,
/// THREAT_MODEL §3). Size is checked before the read.
fn read_file_capped(path: PathBuf, limit: u64) -> std::io::Result<Vec<u8>> {
    let meta = fs::metadata(&path)?;
    if meta.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} exceeds size cap", path.display()),
        ));
    }
    fs::read(&path)
}

/// Optional member: missing -> None; present-but-oversized -> Err (fail-closed reject),
/// so all three verifiers agree on an oversized optional member.
fn read_optional_capped(path: PathBuf, limit: u64) -> Result<Option<Vec<u8>>, String> {
    match read_file_capped(path, limit) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{e}")),
    }
}

// ----------------------------------------------------------------- parse (§8.2)

/// Mirrors Python's `json.loads` + `isinstance(dict)` strictness (and Go's
/// reproduction of it): `serde_json::from_slice::<Value>` already parses
/// exactly one JSON value and rejects trailing non-whitespace bytes (via
/// `Deserializer::end()`), matching `json.loads`'s rejection of trailing
/// data while tolerating trailing whitespace. A non-object top-level value
/// (including JSON `null`) is rejected the same way Python's `isinstance`
/// check and Go's failed type-assertion reject it.
fn parse_manifest(manifest_bytes: &[u8]) -> Result<Map<String, Value>, String> {
    let v: Value = serde_json::from_slice(manifest_bytes).map_err(|e| e.to_string())?;
    let m = match v {
        Value::Object(m) => m,
        _ => return Err("manifest is not a JSON object".to_string()),
    };
    // Only now that the bytes are known to be one well-formed JSON object: a
    // repeated member name was collapsed silently above, and no field may be
    // read until we know the bytes admit only one reading. Same placement as
    // the Go port, so the two report the same detail for the same input.
    if let Some(k) = find_duplicate_key(manifest_bytes) {
        return Err(format!("duplicate JSON key {k:?}"));
    }
    Ok(m)
}

/// find_duplicate_key returns the first key that appears twice inside one and
/// the same JSON object, at any nesting depth (`None` if there is none).
///
/// Why this exists: SPEC §4.1 makes the exact manifest bytes the signed
/// message, so bytes that admit two readings of one field are not a
/// well-formed signed message. Every mainstream JSON library resolves the
/// repeat silently and they do not all agree on how — `serde_json::Map`,
/// Python's `json` and Go's `encoding/json` all keep the LAST value, but that
/// is a library accident, not a protocol rule, and a fourth verifier that
/// kept the first would return a different verdict for identical signed
/// bytes. All three ports therefore reject the repeat outright.
///
/// Why a hand-rolled walk: intercepting map construction in serde needs the
/// `serde` traits as a direct dependency, and this crate deliberately carries
/// only two. The walk stays honest about the hard part by handing each raw
/// quoted key span back to serde_json to unescape, so a key spelled with a
/// unicode escape collides with the same key spelled plainly — exactly as it
/// does for Python's `object_pairs_hook` and Go's `json.Decoder` token
/// stream, which both compare decoded keys too.
///
/// The walk assumes `bytes` already parsed as one JSON value — the caller
/// parses first and returns the library's own error on malformed input —
/// which is what lets this skip validation and merely track container
/// nesting. The two give-up branches below (an unterminated string, a key
/// span serde_json will not decode) are therefore unreachable for anything
/// that reaches here; they return "no duplicate" rather than invent one,
/// since a malformed document has already been rejected upstream.
fn find_duplicate_key(bytes: &[u8]) -> Option<String> {
    enum Frame {
        // `expect_key` is what distinguishes a key from a value: it is set by
        // `{` and by `,`, and cleared by `:`.
        Object {
            seen: HashSet<String>,
            expect_key: bool,
        },
        Array,
    }

    let mut stack: Vec<Frame> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                stack.push(Frame::Object {
                    seen: HashSet::new(),
                    expect_key: true,
                });
                i += 1;
            }
            b'[' => {
                stack.push(Frame::Array);
                i += 1;
            }
            b'}' | b']' => {
                stack.pop();
                i += 1;
            }
            b',' => {
                if let Some(Frame::Object { expect_key, .. }) = stack.last_mut() {
                    *expect_key = true;
                }
                i += 1;
            }
            b':' => {
                if let Some(Frame::Object { expect_key, .. }) = stack.last_mut() {
                    *expect_key = false;
                }
                i += 1;
            }
            b'"' => {
                let end = scan_string_end(bytes, i)?;
                if let Some(Frame::Object { seen, expect_key }) = stack.last_mut() {
                    if *expect_key {
                        let key: String = serde_json::from_slice(&bytes[i..end]).ok()?;
                        if !seen.insert(key.clone()) {
                            return Some(key);
                        }
                    }
                }
                i = end;
            }
            // Whitespace and the bytes of numbers/true/false/null: none of
            // them can be a structural character or a quote, so stepping one
            // byte at a time is enough.
            _ => i += 1,
        }
    }
    None
}

/// scan_string_end takes the index of an opening `"` and returns the index one
/// past the matching closing `"`, or `None` if the string is unterminated.
///
/// A byte scan is exact here: `"` and `\` are single-byte ASCII code points
/// that can never appear as a continuation byte of a multi-byte UTF-8
/// sequence — the same reasoning `normalize_diff` relies on.
fn scan_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut j = start + 1;
    while j < bytes.len() {
        match bytes[j] {
            // Skip the escape AND the byte it escapes; for `\uXXXX` the four
            // hex digits that follow are ordinary bytes that cannot be `"`.
            b'\\' => j += 2,
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

fn version_supported(m: &Map<String, Value>) -> bool {
    match m.get("spec_version").and_then(Value::as_str) {
        Some(v) => v == SPEC_MAJOR || v.starts_with("scpe/0."),
        None => false,
    }
}

// ------------------------------------------------------- resolve identity (§8.3)

/// Safe-subject rule (SPEC §8): full charset match of
/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` AND no `..` substring. Bars `/`,
/// whitespace, `@`, `:`, and path traversal. Implemented as a plain
/// byte/char scan (no regex crate) since the charset is ASCII-only: any
/// non-ASCII byte fails the class check regardless.
fn subject_ok(subject: &str) -> bool {
    let bytes = subject.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    for &b in &bytes[1..] {
        if !(b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
            return false;
        }
    }
    !subject.contains("..")
}

/// The fixed provider registry (SPEC §8/§11.1). This table — and nothing in
/// the manifest — decides which host is contacted for keys.
/// `Some(None)` == the `local` provider (no network fetch; keys come from
/// an owner-supplied file only). `None` == provider absent from the
/// registry (unknown, or reserved-but-not-yet-implemented such as `oidc`)
/// -> unsupported-provider.
fn provider_host(provider: &str) -> Option<Option<&'static str>> {
    match provider {
        "github" => Some(Some("github.com")),
        "gitlab" => Some(Some("gitlab.com")),
        "codeberg" => Some(Some("codeberg.org")),
        "local" => Some(None),
        _ => None,
    }
}

// ------------------------------------------------------------ fetch keys (§8.4)

/// fetchKeys would fetch `https://<host>/<subject>.keys` — HTTPS only, TLS
/// validated, no redirects followed, same contract as the Go/Python
/// references. It is intentionally NOT implemented in this port: the 18
/// normative vectors all supply a `keys` file (test-vectors README), so the
/// network path is never exercised by the conformance suite. Rather than
/// faking network I/O, this returns an honest error.
fn fetch_keys(_host: &str, _subject: &str) -> Result<Vec<u8>, String> {
    Err("network fetch not implemented in the Rust port; supply --keys".to_string())
}

// --------------------------------------------- allowed signers + SSHSIG (§8.5-6)

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A dependency-free temp-directory allocator: `std::env::temp_dir()` plus a
/// unique subdirectory built from the process id and a per-process atomic
/// counter (no reliance on wall-clock time or any RNG crate).
fn make_temp_dir() -> std::io::Result<PathBuf> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    for _ in 0..1000 {
        let n = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("scpe-verify-{pid}-{n}"));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "could not allocate a unique scpe-verify temp dir",
    ))
}

/// verifySignature shells out to `ssh-keygen -Y verify`, exactly as the
/// Go/Python references do, building a one-line-per-key allowed_signers
/// file with principal = subject.
fn verify_signature(manifest_bytes: &[u8], sig_bytes: &[u8], subject: &str, keys_bytes: &[u8]) -> bool {
    let key_lines: Vec<String> = String::from_utf8_lossy(keys_bytes)
        .split('\n')
        .map(|ln| ln.trim().to_string())
        .filter(|ln| !ln.is_empty())
        .collect();
    if key_lines.is_empty() {
        return false;
    }

    let mut signers = String::new();
    for ln in &key_lines {
        signers.push_str(&format!("{subject} namespaces=\"{NAMESPACE}\" {ln}\n"));
    }

    let td = match make_temp_dir() {
        Ok(d) => d,
        Err(_) => return false,
    };

    let outcome = (|| -> bool {
        let allowed_signers_path = td.join("allowed_signers");
        let sig_path = td.join("manifest.sig");
        if fs::write(&allowed_signers_path, signers.as_bytes()).is_err() {
            return false;
        }
        if fs::write(&sig_path, sig_bytes).is_err() {
            return false;
        }

        let mut child = match Command::new("ssh-keygen")
            .arg("-Y")
            .arg("verify")
            .arg("-f")
            .arg(&allowed_signers_path)
            .arg("-I")
            .arg(subject)
            .arg("-n")
            .arg(NAMESPACE)
            .arg("-s")
            .arg(&sig_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        // Write the manifest to stdin on a separate thread while we wait for
        // output, so a manifest larger than the OS pipe buffer can't
        // deadlock against ssh-keygen filling its own stdout/stderr buffer
        // (mirrors Go's exec.Command, which does the same internally).
        let stdin = child.stdin.take();
        let manifest_owned = manifest_bytes.to_vec();
        let writer = stdin.map(|mut s| {
            std::thread::spawn(move || {
                let _ = s.write_all(&manifest_owned);
                // `s` drops here, closing the pipe.
            })
        });

        let output = child.wait_with_output();
        if let Some(w) = writer {
            let _ = w.join();
        }

        matches!(output, Ok(o) if o.status.success())
    })();

    let _ = fs::remove_dir_all(&td);
    outcome
}

// ------------------------------------------------------------- integrity (§8.7)

/// normalizeDiff mirrors SPEC §6: UTF-8, CRLF/CR -> LF, exactly one
/// trailing newline. Byte-level (no UTF-8 decode round-trip) since `\r`
/// (0x0D) and `\n` (0x0A) are always single-byte ASCII code points and can
/// never appear as a continuation byte of a multi-byte UTF-8 sequence — a
/// byte scan is therefore exact for well-formed UTF-8 diffs, same
/// reasoning the Go port uses.
fn normalize_diff(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\r' {
            out.push(b'\n');
            if i + 1 < raw.len() && raw[i + 1] == b'\n' {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    while out.last() == Some(&b'\n') {
        out.pop();
    }
    out.push(b'\n');
    out
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for byte in digest {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// codeChangeIntegrityOK: SPEC §6 — the SHA-256 of the normalized diff MUST
/// equal subject.change.diff_sha256.
fn code_change_integrity_ok(subject: &Map<String, Value>, diff_bytes: &[u8]) -> bool {
    let want = subject
        .get("change")
        .and_then(Value::as_object)
        .and_then(|c| c.get("diff_sha256"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if want.is_empty() {
        return false;
    }
    sha256_hex(&normalize_diff(diff_bytes)) == want
}

/// artifactIntegrityOK: SPEC §6.2 — the SHA-256 of the RAW enclosed
/// artifact bytes MUST equal subject.digest.sha256. No normalization.
fn artifact_integrity_ok(subject: &Map<String, Value>, artifact_bytes: &[u8]) -> bool {
    let want = subject
        .get("digest")
        .and_then(Value::as_object)
        .and_then(|d| d.get("sha256"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if want.is_empty() {
        return false;
    }
    sha256_hex(artifact_bytes) == want
}

// ---------------------------------------------------- attestation status (§8 step 8)

fn one_attestation_status(att: &Value) -> String {
    let m = match att.as_object() {
        Some(m) => m,
        None => return "present-unverified".to_string(),
    };
    let atype = m.get("type").and_then(Value::as_str);
    let format = m.get("format").and_then(Value::as_str);
    if atype == Some("agent-trace") {
        if let Some(f) = format {
            if REGISTERED_TRACE_FORMATS.contains(&f) {
                return format!("present-{f}");
            }
        }
    }
    "present-unverified".to_string()
}

/// attestationsSummary: the per-attestation [{type, status}] summary (SPEC
/// §8 step 8). An absent or empty `attestations` list yields []; a
/// non-list is treated as no attestations.
fn attestations_summary(m: &Map<String, Value>) -> Vec<AttEntry> {
    let atts = match m.get("attestations").and_then(Value::as_array) {
        Some(a) => a,
        None => return vec![],
    };
    atts.iter()
        .map(|att| {
            let atype = att
                .as_object()
                .and_then(|m| m.get("type"))
                .cloned()
                .unwrap_or(Value::Null);
            AttEntry {
                r#type: atype,
                status: one_attestation_status(att),
            }
        })
        .collect()
}

fn is_all_whitespace(b: &[u8]) -> bool {
    b.iter()
        .all(|&c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C))
}

// ------------------------------------------------------------------ verify (§8)

/// Options carries the CLI overrides that substitute for what would
/// otherwise be enclosed in the envelope or fetched over the network —
/// exactly the Go/Python reference's --keys / --diff / --artifact.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub keys_file: Option<PathBuf>,
    pub diff_file: Option<PathBuf>,
    pub artifact_file: Option<PathBuf>,
}

/// verify runs SPEC.md §8 against the given path (a vector directory in
/// this port; see module doc for the two stubbed input forms) and returns
/// the same status strings as the Go/Python reference verifiers.
pub fn verify(path: &Path, opts: &Options) -> VerifyResult {
    // 1. locate
    let loaded = match load_input(path) {
        Ok(l) => l,
        Err(e) => return simple_result("unattested", &e),
    };

    // 2. parse + version
    let m = match parse_manifest(&loaded.manifest) {
        Ok(m) => m,
        Err(e) => return simple_result("signature-invalid", &format!("manifest unparsable: {e}")),
    };

    // The advisory `profile` label (SPEC §13) is surfaced verbatim on every
    // post-parse outcome but never dispatched.
    let profile = m.get("profile").and_then(Value::as_str).map(str::to_string);
    // Assigned in step 4 and read back through `r`, so every outcome downstream
    // of the key selection discloses its anchor and every outcome upstream of
    // it reports None. A Cell because `r` has to read a value written after it
    // is defined, which a plain `mut` binding would not allow.
    let key_source: Cell<Option<KeySource>> = Cell::new(None);
    let r = |status: &str, detail: &str, attestations: Vec<AttEntry>| -> VerifyResult {
        VerifyResult {
            status: status.to_string(),
            detail: detail.to_string(),
            attestations,
            profile: profile.clone(),
            key_source: key_source.get(),
        }
    };

    if !version_supported(&m) {
        let sv = m.get("spec_version").cloned().unwrap_or(Value::Null);
        return r(
            "unsupported-version",
            &format!("spec_version {}", display_type(&sv)),
            vec![],
        );
    }

    // 3. resolve the provider (§8 step 3).
    let identity = m
        .get("contributor")
        .and_then(Value::as_object)
        .and_then(|c| c.get("identity"))
        .and_then(Value::as_object);

    let provider = identity
        .and_then(|i| i.get("provider"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let subject_opt = identity.and_then(|i| i.get("subject")).and_then(Value::as_str);

    let host_lookup = provider_host(provider);
    if host_lookup.is_none() {
        return r(
            "unsupported-provider",
            &format!("provider {provider:?} is not in the fixed registry"),
            vec![],
        );
    }
    let host = host_lookup.unwrap(); // Option<&str>: None == the `local` provider

    let subject = match subject_opt {
        Some(s) if subject_ok(s) => s,
        _ => return r("identity-unverifiable", "missing or malformed subject", vec![]),
    };

    // 4. keys — --keys flag > keys file shipped beside the manifest > network.
    //    Whichever tier wins is recorded: the precedence is unchanged, but the
    //    answer is no longer silent (see KeySource for why `bundled` in
    //    particular has to be visible).
    let mut keys_bytes = loaded.keys;
    let mut source = KeySource::Bundled;
    if let Some(kf) = &opts.keys_file {
        match fs::read(kf) {
            Ok(b) => {
                keys_bytes = Some(b);
                source = KeySource::Flag;
            }
            Err(e) => {
                return r(
                    "identity-unverifiable",
                    &format!("cannot read --keys file: {e}"),
                    vec![],
                )
            }
        }
    }
    let keys_bytes = match keys_bytes {
        Some(b) => b,
        None => {
            if host.is_none() {
                return r(
                    "identity-unverifiable",
                    "local provider requires an owner-supplied keys file",
                    vec![],
                );
            }
            match fetch_keys(host.unwrap(), subject) {
                Ok(b) => {
                    source = KeySource::Forge;
                    b
                }
                Err(e) => {
                    return r(
                        "identity-unverifiable",
                        &format!("key fetch failed: {e}"),
                        vec![],
                    )
                }
            }
        }
    };
    // Claimed only once bytes are actually in hand: the three returns above got
    // none, so they must not name a tier they never read from.
    key_source.set(Some(source));
    if is_all_whitespace(&keys_bytes) {
        return r("identity-unverifiable", "no published keys", vec![]);
    }

    // 5-6. allowed signers + SSHSIG
    if !verify_signature(&loaded.manifest, &loaded.sig, subject, &keys_bytes) {
        return r("signature-invalid", "SSHSIG verification failed", vec![]);
    }

    // 7. subject integrity — dispatch on the SIGNED subject.type (SPEC §6).
    let subject_block = m.get("subject").and_then(Value::as_object);
    let stype = subject_block
        .and_then(|s| s.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let empty_map = Map::new();

    match stype {
        "code-change" => {
            let mut diff_bytes = loaded.diff;
            if let Some(df) = &opts.diff_file {
                match fs::read(df) {
                    Ok(b) => diff_bytes = Some(b),
                    Err(e) => {
                        return r("tampered", &format!("cannot read --diff file: {e}"), vec![])
                    }
                }
            }
            let diff_bytes = match diff_bytes {
                Some(b) => b,
                None => {
                    return r(
                        "tampered",
                        "no diff available to check integrity against",
                        vec![],
                    )
                }
            };
            let sb = subject_block.unwrap_or(&empty_map);
            if !code_change_integrity_ok(sb, &diff_bytes) {
                return r(
                    "tampered",
                    "diff sha256 does not match subject.change.diff_sha256",
                    vec![],
                );
            }
        }
        "artifact" => {
            let mut artifact_bytes = loaded.artifact;
            if let Some(af) = &opts.artifact_file {
                match fs::read(af) {
                    Ok(b) => artifact_bytes = Some(b),
                    Err(e) => {
                        return r(
                            "tampered",
                            &format!("cannot read --artifact file: {e}"),
                            vec![],
                        )
                    }
                }
            }
            let artifact_bytes = match artifact_bytes {
                Some(b) => b,
                None => {
                    return r(
                        "tampered",
                        "no artifact payload to check integrity against",
                        vec![],
                    )
                }
            };
            let sb = subject_block.unwrap_or(&empty_map);
            if !artifact_integrity_ok(sb, &artifact_bytes) {
                return r(
                    "tampered",
                    "artifact sha256 does not match subject.digest.sha256",
                    vec![],
                );
            }
        }
        other => {
            return r(
                "unsupported-subject",
                &format!("subject type {other:?} is not implemented in scpe/0.1"),
                vec![],
            );
        }
    }

    // 8. verified — with the per-attestation {type, status} summary.
    r("verified", "", attestations_summary(&m))
}

// -------------------------------------------------------------------- tests

/// The duplicate-key walk is the only hand-rolled JSON handling in this port,
/// and the 18 normative vectors contain no repeated key — so it is the one
/// piece the conformance gate cannot exercise. These cases cover it directly.
#[cfg(test)]
mod tests {
    use super::{find_duplicate_key, parse_manifest};

    #[test]
    fn flat_duplicate_is_found() {
        assert_eq!(
            find_duplicate_key(br#"{"spec_version":"scpe/0.1","spec_version":"scpe/9.9"}"#),
            Some("spec_version".to_string())
        );
    }

    #[test]
    fn nested_duplicate_is_found() {
        // The dangerous case the adversarial vector cannot show: a repeat deep
        // in the identity block resolves silently and could still reach
        // `verified` under last-wins.
        assert_eq!(
            find_duplicate_key(
                br#"{"contributor":{"identity":{"subject":"octocat","subject":"attacker"}}}"#
            ),
            Some("subject".to_string())
        );
    }

    #[test]
    fn same_key_in_sibling_objects_is_not_a_duplicate() {
        assert_eq!(
            find_duplicate_key(br#"{"attestations":[{"type":"a"},{"type":"b"}]}"#),
            None
        );
    }

    #[test]
    fn same_key_in_an_enclosing_object_is_not_a_duplicate() {
        assert_eq!(find_duplicate_key(br#"{"type":{"type":"nested"}}"#), None);
    }

    #[test]
    fn strings_are_skipped_whole() {
        // Structural bytes inside a key and inside a value must not steer the
        // walk, or a crafted manifest could hide a repeat from it.
        assert_eq!(find_duplicate_key(br#"{"a{,:}b":1,"c":2}"#), None);
        assert_eq!(find_duplicate_key(br#"{"a":"{,:}","b":"a"}"#), None);
    }

    #[test]
    fn escaped_and_plain_spellings_of_one_key_collide() {
        // An object whose second key is the six-character unicode escape for
        // the letter `a`, spelled byte-wise (0x5c is the backslash) so the
        // test data cannot be quietly normalized by an editor. Both keys
        // decode to "a", so this is a repeat that a raw-span comparison would
        // miss and that Python and Go both catch.
        let bytes: [u8; 18] = [
            b'{', b'"', b'a', b'"', b':', b'1', b',', b'"', 0x5c, b'u', b'0', b'0', b'6', b'1',
            b'"', b':', b'2', b'}',
        ];
        assert_eq!(find_duplicate_key(&bytes), Some("a".to_string()));
    }

    #[test]
    fn a_clean_manifest_has_no_duplicate() {
        assert_eq!(
            find_duplicate_key(
                br#"{"spec_version":"scpe/0.1","contributor":{"identity":{"provider":"github","subject":"octocat-test"}},"subject":{"type":"artifact","digest":{"sha256":"ab"}}}"#
            ),
            None
        );
    }

    #[test]
    fn parse_manifest_reports_the_offending_key() {
        assert_eq!(
            parse_manifest(br#"{"a":1,"a":2}"#).unwrap_err(),
            r#"duplicate JSON key "a""#
        );
    }

    #[test]
    fn parse_manifest_still_accepts_a_clean_object() {
        let m = parse_manifest(br#"{"spec_version":"scpe/0.1"}"#).expect("clean manifest parses");
        assert_eq!(m.get("spec_version").and_then(|v| v.as_str()), Some("scpe/0.1"));
    }
}
