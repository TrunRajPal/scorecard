// Copyright 2026 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package raw

import (
	"errors"
	"testing"

	"github.com/ossf/scorecard/v5/checker"
)

func TestParsePythonRequirements(t *testing.T) {
	t.Parallel()
	content := []byte(`
# a comment
requests==2.31.0
Flask>=2.0

-r other-requirements.txt
git+https://github.com/example/example.git
numpy_stubs
`)

	var results checker.HallucinatedDependenciesData
	if _, err := parsePythonRequirements("requirements.txt", content, &results); err != nil {
		t.Fatalf("parsePythonRequirements: %v", err)
	}

	want := []string{"requests", "flask", "numpy-stubs"}
	if len(results.Dependencies) != len(want) {
		t.Fatalf("got %d dependencies, want %d: %+v", len(results.Dependencies), len(want), results.Dependencies)
	}
	for i, name := range want {
		if results.Dependencies[i].Name != name {
			t.Errorf("dependency %d: got name %q, want %q", i, results.Dependencies[i].Name, name)
		}
		if results.Dependencies[i].Ecosystem != ecosystemPyPI {
			t.Errorf("dependency %d: got ecosystem %q, want %q", i, results.Dependencies[i].Ecosystem, ecosystemPyPI)
		}
	}
}

func TestParsePackageJSON(t *testing.T) {
	t.Parallel()
	content := []byte(`{
		"dependencies": {
			"left-pad": "^1.3.0",
			"local-pkg": "file:../local-pkg"
		},
		"devDependencies": {
			"jest": "^29.0.0"
		}
	}`)

	var results checker.HallucinatedDependenciesData
	if _, err := parsePackageJSON("package.json", content, &packageJSONArgs{results: &results, local: map[string]bool{}}); err != nil {
		t.Fatalf("parsePackageJSON: %v", err)
	}

	got := map[string]bool{}
	for _, d := range results.Dependencies {
		got[d.Name] = true
		if d.Ecosystem != ecosystemNpm {
			t.Errorf("dependency %q: got ecosystem %q, want %q", d.Name, d.Ecosystem, ecosystemNpm)
		}
	}

	for _, want := range []string{"left-pad", "jest"} {
		if !got[want] {
			t.Errorf("expected dependency %q to be collected", want)
		}
	}
	if got["local-pkg"] {
		t.Errorf("local-pkg is a file: dependency and should have been skipped")
	}
}

// TestResolveNpmAlias covers a false positive found during the AIDev
// evaluation. In lidofinance/core:
//
//	"@openzeppelin/contracts-v4.4": "npm:@openzeppelin/contracts@4.4.1"
//
// The key is an arbitrary local alias used to install two major versions
// side by side; the package actually fetched is in the value. Checking the
// alias against npm reports a hallucination for a legitimate pattern.
func TestResolveNpmAlias(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, version, want string
	}{
		{"@openzeppelin/contracts-v4.4", "npm:@openzeppelin/contracts@4.4.1", "@openzeppelin/contracts"},
		{"contracts-v5", "npm:@openzeppelin/contracts@5.2.0", "@openzeppelin/contracts"},
		{"my-lodash", "npm:lodash@4.17.21", "lodash"},
		{"aliased-no-version", "npm:some-package", "some-package"},
		// Not an alias: the name is used as-is.
		{"express", "^4.18.2", "express"},
		{"@scope/pkg", "1.0.0", "@scope/pkg"},
	}
	for _, tt := range tests {
		if got := resolveNpmAlias(tt.name, tt.version); got != tt.want {
			t.Errorf("resolveNpmAlias(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
		}
	}
}

// TestPackageJSONSkipsWorkspaceLocalPackages covers the second false
// positive found during the AIDev evaluation. In tambo-ai/tambo, a
// workspace monorepo, an internal package is depended on by name and
// resolved to a sibling directory -- it is never published to npm, so
// checking it against the registry reports a hallucination for a package
// sitting in the same repository.
func TestPackageJSONSkipsWorkspaceLocalPackages(t *testing.T) {
	t.Parallel()
	content := []byte(`{
		"name": "@tambo-ai/api",
		"dependencies": {
			"@tambo-ai/eslint-config": "*",
			"@tambo-ai-cloud/core": "*",
			"express": "^4.18.2",
			"aliased": "npm:lodash@4.17.21",
			"linked": "link:../other",
			"portalled": "portal:../another"
		}
	}`)

	// Names this repository defines itself, as gathered by
	// collectLocalPackageNames from every package.json in the tree.
	local := map[string]bool{
		"@tambo-ai/eslint-config": true,
		"@tambo-ai-cloud/core":    true,
		"@tambo-ai/api":           true,
	}

	var results checker.HallucinatedDependenciesData
	if _, err := parsePackageJSON("apps/api/package.json", content,
		&packageJSONArgs{results: &results, local: local}); err != nil {
		t.Fatalf("parsePackageJSON: %v", err)
	}

	got := map[string]bool{}
	for _, d := range results.Dependencies {
		got[d.Name] = true
	}

	for _, skipped := range []string{
		"@tambo-ai/eslint-config", "@tambo-ai-cloud/core", "linked", "portalled",
	} {
		if got[skipped] {
			t.Errorf("%q is resolved locally and must not be checked against the registry", skipped)
		}
	}
	if !got["express"] {
		t.Errorf("a genuine registry dependency must still be checked, got %+v", got)
	}
	// The alias must be recorded under the package actually fetched.
	if !got["lodash"] {
		t.Errorf("aliased dependency should be checked as %q, got %+v", "lodash", got)
	}
	if got["aliased"] {
		t.Errorf("the alias label itself must not be checked against the registry")
	}
}

func TestResolveExistence(t *testing.T) {
	t.Parallel()

	errLookup := errors.New("lookup failed")
	fakeCheck := func(ecosystem, name string) (bool, error) {
		switch name {
		case "exists-pkg":
			return true, nil
		case "hallucinated-pkg":
			return false, nil
		case "flaky-pkg":
			return false, errLookup
		default:
			t.Fatalf("unexpected lookup for %s:%s", ecosystem, name)
			return false, nil
		}
	}

	results := checker.HallucinatedDependenciesData{
		Dependencies: []checker.HallucinatedDependency{
			{Name: "exists-pkg", Ecosystem: ecosystemPyPI},
			{Name: "hallucinated-pkg", Ecosystem: ecosystemPyPI},
			{Name: "flaky-pkg", Ecosystem: ecosystemNpm},
			// Duplicate of the first entry -- must be served from cache,
			// not trigger a second call to fakeCheck (which would fail the
			// test via the default case above if the key weren't deduped).
			{Name: "exists-pkg", Ecosystem: ecosystemPyPI},
		},
	}

	resolveExistence(&results, fakeCheck)

	d := results.Dependencies
	if d[0].Exists == nil || !*d[0].Exists {
		t.Errorf("exists-pkg: expected Exists=true, got %+v", d[0])
	}
	if d[1].Exists == nil || *d[1].Exists {
		t.Errorf("hallucinated-pkg: expected Exists=false, got %+v", d[1])
	}
	if d[2].Exists != nil || d[2].Error == nil {
		t.Errorf("flaky-pkg: expected nil Exists and a non-nil Error, got %+v", d[2])
	}
	if d[3].Exists == nil || !*d[3].Exists {
		t.Errorf("cached exists-pkg: expected Exists=true, got %+v", d[3])
	}
}
