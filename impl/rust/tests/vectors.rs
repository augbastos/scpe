//! Conformance gate for the Rust SCPE verifier: SPEC.md's Appendix A says an
//! implementation that produces the expected status for all eighteen
//! normative vectors under spec/test-vectors/ conforms to §8. This mirrors
//! impl/go/internal/scpe/vectors_test.go — each vector's `keys` file
//! substitutes for the network fetch of §8 step 4, exactly as the
//! test-vectors README requires.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

use scpe_verify::scpe::{verify, Options};

/// Locates spec/test-vectors relative to this crate's manifest dir
/// (impl/rust), independent of the test runner's working directory.
fn test_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors")
}

/// Reads expected.json and returns (status, Some(list of (type, status))
/// if "attestations" was present, else None) — attestations are checked
/// only when present, matching the vectors README.
fn read_expected(expected_path: &std::path::Path) -> (String, Option<Vec<(Value, String)>>) {
    let raw = fs::read(expected_path)
        .unwrap_or_else(|e| panic!("reading {expected_path:?}: {e}"));
    let v: Value =
        serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("parsing {expected_path:?}: {e}"));
    let status = v
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let attestations = v.get("attestations").and_then(Value::as_array).map(|arr| {
        arr.iter()
            .map(|e| {
                let t = e.get("type").cloned().unwrap_or(Value::Null);
                let s = e
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                (t, s)
            })
            .collect()
    });
    (status, attestations)
}

#[test]
fn all_18_vectors_conform() {
    let root_raw = test_vectors_dir();
    let root = fs::canonicalize(&root_raw)
        .unwrap_or_else(|e| panic!("spec/test-vectors not found at {root_raw:?}: {e}"));

    let mut names: Vec<String> = fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("reading {root:?}: {e}"))
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n != "_key")
        .collect();
    names.sort();

    assert_eq!(
        names.len(),
        18,
        "expected 18 test vectors, found {}: {:?}",
        names.len(),
        names
    );

    let mut failures: Vec<String> = Vec::new();
    let mut matched = 0usize;

    for name in &names {
        let vec_dir = root.join(name);
        let (want_status, want_atts) = read_expected(&vec_dir.join("expected.json"));

        let mut opts = Options::default();
        let keys_path = vec_dir.join("keys");
        if keys_path.is_file() {
            // Mirror the Go/Python verifier's --keys substitution: the
            // vector's `keys` file stands in for the network fetch.
            opts.keys_file = Some(keys_path);
        }

        let got = verify(&vec_dir, &opts);

        if got.status != want_status {
            failures.push(format!(
                "{name}: status = {:?}, want {:?} (detail: {})",
                got.status, want_status, got.detail
            ));
            continue;
        }

        if let Some(want_atts) = &want_atts {
            if got.attestations.len() != want_atts.len() {
                failures.push(format!(
                    "{name}: attestations len = {}, want {} (got: {:?})",
                    got.attestations.len(),
                    want_atts.len(),
                    got.attestations
                ));
                continue;
            }
            let mut ok = true;
            for (i, (want_type, want_status)) in want_atts.iter().enumerate() {
                if &got.attestations[i].r#type != want_type || &got.attestations[i].status != want_status
                {
                    failures.push(format!(
                        "{name}: attestations[{i}] = {{type: {:?}, status: {:?}}}, want {{type: {:?}, status: {:?}}}",
                        got.attestations[i].r#type, got.attestations[i].status, want_type, want_status
                    ));
                    ok = false;
                }
            }
            if !ok {
                continue;
            }
        }

        matched += 1;
    }

    assert!(
        failures.is_empty(),
        "conformance: {matched}/{} vectors matched.\nfailures:\n{}",
        names.len(),
        failures.join("\n")
    );
    assert_eq!(matched, names.len());
}
