package scpe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// testVectorsDir locates spec/test-vectors relative to this file's package,
// independent of the caller's working directory (go test may be invoked from
// the module root or from this package's directory).
func testVectorsDir(t *testing.T) string {
	t.Helper()
	dir := "../../../../spec/test-vectors"
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("resolving test-vectors dir: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("spec/test-vectors not found at %s: %v", abs, err)
	}
	return abs
}

type expectedResult struct {
	Status       string     `json:"status"`
	Attestations []AttEntry `json:"attestations,omitempty"`
}

// TestAllVectors is the status conformance gate: SPEC.md's Appendix A says an
// implementation that produces the expected status for all eighteen normative
// vectors under spec/test-vectors/ conforms to §8's *status* behaviour. It is
// not the whole of §8 -- no vector carries an expected key_source, so a green
// run here does not by itself show that step 4's key_source MUST is honoured.
// Each vector's `keys` file substitutes for the network fetch of §8 step 4,
// exactly as the test-vectors README requires (passed here via
// --keys-equivalent Options, so these runs resolve at the `flag` anchor and
// never reach `forge`).
func TestAllVectors(t *testing.T) {
	root := testVectorsDir(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading %s: %v", root, err)
	}

	var vectorNames []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "_key" {
			continue
		}
		vectorNames = append(vectorNames, e.Name())
	}
	sort.Strings(vectorNames)

	if len(vectorNames) != 18 {
		t.Fatalf("expected 18 test vectors, found %d: %v", len(vectorNames), vectorNames)
	}

	matched := 0
	for _, name := range vectorNames {
		name := name
		t.Run(name, func(t *testing.T) {
			vecDir := filepath.Join(root, name)
			expBytes, err := os.ReadFile(filepath.Join(vecDir, "expected.json"))
			if err != nil {
				t.Fatalf("reading expected.json: %v", err)
			}
			var want expectedResult
			if err := json.Unmarshal(expBytes, &want); err != nil {
				t.Fatalf("parsing expected.json: %v", err)
			}

			keysPath := filepath.Join(vecDir, "keys")
			opts := Options{}
			if _, err := os.Stat(keysPath); err == nil {
				// Mirror the Python verifier's --keys substitution: the vector's
				// `keys` file stands in for the network fetch (test-vectors README).
				opts.KeysFile = keysPath
			}

			got := Verify(vecDir, opts)
			if got.Status != want.Status {
				t.Errorf("%s: status = %q, want %q (detail: %s)", name, got.Status, want.Status, got.Detail)
				return
			}

			if want.Attestations != nil {
				if len(got.Attestations) != len(want.Attestations) {
					t.Errorf("%s: attestations = %+v, want %+v", name, got.Attestations, want.Attestations)
					return
				}
				for i := range want.Attestations {
					if got.Attestations[i].Type != want.Attestations[i].Type ||
						got.Attestations[i].Status != want.Attestations[i].Status {
						t.Errorf("%s: attestations[%d] = %+v, want %+v", name, i, got.Attestations[i], want.Attestations[i])
						return
					}
				}
			}

			matched++
		})
	}

	t.Logf("conformance: %d/%d vectors matched expected status", matched, len(vectorNames))
}
