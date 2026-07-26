// Command scpe-verify is the Go port of reference/standalone/verify_envelope.py:
// a stdlib-only SCPE scpe/0.1 verifier. It implements SPEC.md §8 verbatim.
//
// Usage:
//
//	scpe-verify <path> [--keys FILE] [--diff FILE] [--artifact FILE] [--json]
//
// <path> is one of:
//
//	a directory containing manifest.json + manifest.sig (+ diff.patch, keys)
//	an envelope zip containing exactly those members
//	a file holding an SCPE-ATTESTATION-v1 block (e.g. a saved PR body)
//
// --keys FILE      use FILE as the body of <provider-host>/<subject>.keys
//
//	instead of fetching (offline verification; required by the
//	test vectors, and the only key source for the `local` provider).
//
// --diff FILE      verify integrity against this diff (attestation form,
//
//	where the diff is not enclosed and normally comes from the PR).
//
// --artifact FILE  verify an `artifact` subject against these bytes
//
//	(standalone form, where the artifact is not enclosed).
//
// --json           machine-readable output.
//
// Every result reports `key_source`: which tier of the key precedence anchored
// the identity -- `flag` (--keys), `bundled` (a `keys` file carried inside the
// input, so chosen by whoever submitted it), or `forge` (fetched from the
// provider's host). It is null when the verdict was reached before any key was
// read. All three tiers can end in `verified`, so a consumer that cares whether
// an identity was checked against the forge has to read this field, not the
// status.
//
// Exit code 0 iff the result is `verified` -- same contract as the Python
// reference verifier.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/augbastos/scpe/impl/go/internal/scpe"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: scpe-verify <path> [--keys FILE] [--diff FILE] [--artifact FILE] [--json]")
}

// parseArgs is a small argparse-style parser: flags may appear in any order
// relative to the single positional <path>, matching the Python CLI's
// flexibility (Go's stdlib `flag` package stops parsing at the first
// positional argument, which would break `scpe-verify <path> --keys FILE`).
func parseArgs(argv []string) (path string, opts scpe.Options, asJSON bool, err error) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		next := func() (string, error) {
			i++
			if i >= len(argv) {
				return "", fmt.Errorf("%s requires an argument", a)
			}
			return argv[i], nil
		}
		switch a {
		case "--keys":
			if opts.KeysFile, err = next(); err != nil {
				return
			}
		case "--diff":
			if opts.DiffFile, err = next(); err != nil {
				return
			}
		case "--artifact":
			if opts.ArtifactFile, err = next(); err != nil {
				return
			}
		case "--json":
			asJSON = true
		case "-h", "--help":
			usage()
			os.Exit(0)
		default:
			if path != "" {
				err = fmt.Errorf("unexpected argument %q", a)
				return
			}
			path = a
		}
	}
	if path == "" {
		err = fmt.Errorf("missing required argument: path")
	}
	return
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	path, opts, asJSON, err := parseArgs(argv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		usage()
		return 2
	}

	res := scpe.Verify(path, opts)

	if asJSON {
		out := map[string]interface{}{
			"status":       res.Status,
			"attestations": res.Attestations,
			"profile":      nil,
			"key_source":   nil,
			"detail":       res.Detail,
		}
		if res.Profile != nil {
			out["profile"] = *res.Profile
		}
		// Always emitted, null when no key was consulted -- same contract as
		// `profile`, so a consumer can read the anchor without probing for the
		// field's existence.
		if res.KeySource != nil {
			out["key_source"] = *res.KeySource
		}
		enc, _ := json.Marshal(out)
		fmt.Println(string(enc))
	} else {
		mark := "NO"
		if res.Status == "verified" {
			mark = "OK"
		}
		line := fmt.Sprintf("[%s] %s", mark, res.Status)
		if res.Status == "verified" {
			if len(res.Attestations) > 0 {
				summ := ""
				for i, a := range res.Attestations {
					if i > 0 {
						summ += ", "
					}
					summ += fmt.Sprintf("%v=%s", a.Type, a.Status)
				}
				line += fmt.Sprintf(" (attestations: %s)", summ)
			} else {
				line += " (attestations: none)"
			}
		}
		if res.Profile != nil && *res.Profile != "" {
			line += fmt.Sprintf(" [profile: %s]", *res.Profile)
		}
		// A bare "[OK] verified" reads the same whether the keys came from the
		// forge or from the submitted package itself; the anchor is printed so a
		// human reading one line is not left to assume the stronger of the two.
		if res.KeySource != nil {
			line += fmt.Sprintf(" [key_source: %s]", *res.KeySource)
		}
		if res.Detail != "" {
			line += " — " + res.Detail
		}
		fmt.Println(line)
	}

	if res.Status == "verified" {
		return 0
	}
	return 1
}
