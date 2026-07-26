//! Command scpe-verify is the Rust port of reference/standalone/verify_envelope.py
//! (and impl/go/cmd/scpe-verify): a SCPE scpe/0.1 verifier CLI. It implements
//! SPEC.md §8 via `scpe_verify::scpe::verify` and reproduces the Go/Python
//! text and --json output formats byte-for-byte.
//!
//! Usage:
//!
//!     scpe-verify <path> [--keys FILE] [--diff FILE] [--artifact FILE] [--json]
//!
//! <path> is a directory containing manifest.json + manifest.sig (+
//! diff.patch/artifact.bin/keys) — the only input form this port
//! implements (see src/scpe.rs module doc for why).
//!
//! --keys FILE      use FILE as the body of <provider-host>/<subject>.keys
//!                   instead of fetching (offline verification; required by
//!                   the test vectors, and the only key source for the
//!                   `local` provider).
//! --diff FILE       verify integrity against this diff (attestation form,
//!                   where the diff is not enclosed and normally comes from
//!                   the PR).
//! --artifact FILE   verify an `artifact` subject against these bytes
//!                   (standalone form, where the artifact is not enclosed).
//! --json            machine-readable output: `status`, `attestations`,
//!                   `profile`, `key_source` and `detail`.
//!
//! `key_source` is "flag" | "bundled" | "forge" — which tier of SPEC §8 step 4
//! supplied the public keys — or null when no key bytes were ever consulted.
//! It matters because `bundled` keys ride inside the input and are chosen by
//! whoever submitted it, so a `bundled` pass never involved the provider's
//! host at all. The human line shows the same thing as `[key_source: …]`.
//! Like `profile`, it is always present in `--json` — null rather than absent
//! — so a consumer can read the anchor without probing for the field.
//!
//! Exit code 0 iff the result is `verified` — same contract as the Go and
//! Python reference verifiers.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use scpe_verify::scpe::{self, Options};

fn usage() {
    eprintln!("usage: scpe-verify <path> [--keys FILE] [--diff FILE] [--artifact FILE] [--json]");
}

struct ParsedArgs {
    path: PathBuf,
    opts: Options,
    as_json: bool,
}

/// parseArgs is a small argparse-style parser: flags may appear in any
/// order relative to the single positional <path>, matching the Go/Python
/// CLI's flexibility.
fn parse_args(argv: &[String]) -> Result<ParsedArgs, String> {
    let mut path: Option<String> = None;
    let mut opts = Options::default();
    let mut as_json = false;

    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        let next = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            argv.get(*i)
                .cloned()
                .ok_or_else(|| format!("{a} requires an argument"))
        };
        match a {
            "--keys" => opts.keys_file = Some(PathBuf::from(next(&mut i)?)),
            "--diff" => opts.diff_file = Some(PathBuf::from(next(&mut i)?)),
            "--artifact" => opts.artifact_file = Some(PathBuf::from(next(&mut i)?)),
            "--json" => as_json = true,
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            other => {
                if path.is_some() {
                    return Err(format!("unexpected argument {other:?}"));
                }
                path = Some(other.to_string());
            }
        }
        i += 1;
    }

    let path = path.ok_or_else(|| "missing required argument: path".to_string())?;
    Ok(ParsedArgs {
        path: PathBuf::from(path),
        opts,
        as_json,
    })
}

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().skip(1).collect();
    let parsed = match parse_args(&argv) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            usage();
            return ExitCode::from(2);
        }
    };

    let res = scpe::verify(&parsed.path, &parsed.opts);

    if parsed.as_json {
        let atts: Vec<serde_json::Value> = res
            .attestations
            .iter()
            .map(|a| serde_json::json!({"type": a.r#type, "status": a.status}))
            .collect();
        let out = serde_json::json!({
            "status": res.status,
            "attestations": atts,
            "profile": res.profile,
            "key_source": res.key_source.map(scpe::KeySource::as_str),
            "detail": res.detail,
        });
        println!("{}", serde_json::to_string(&out).unwrap());
    } else {
        let mark = if res.status == "verified" { "OK" } else { "NO" };
        let mut line = format!("[{mark}] {}", res.status);
        if res.status == "verified" {
            if res.attestations.is_empty() {
                line += " (attestations: none)";
            } else {
                let summ: Vec<String> = res
                    .attestations
                    .iter()
                    .map(|a| format!("{}={}", scpe::display_type(&a.r#type), a.status))
                    .collect();
                line += &format!(" (attestations: {})", summ.join(", "));
            }
        }
        if let Some(p) = &res.profile {
            if !p.is_empty() {
                line += &format!(" [profile: {p}]");
            }
        }
        // A bare "[OK] verified" reads the same whether the keys came from the
        // forge or from the submitted package itself; the anchor is printed so a
        // human reading one line is not left to assume the stronger of the two.
        if let Some(ks) = res.key_source {
            line += &format!(" [key_source: {}]", ks.as_str());
        }
        if !res.detail.is_empty() {
            line += &format!(" — {}", res.detail);
        }
        println!("{line}");
    }

    if res.status == "verified" {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
