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
	"time"

	"github.com/ossf/scorecard/v5/checker"
)

func TestParsePinnedPythonRequirements(t *testing.T) {
	t.Parallel()
	content := []byte(`
# a comment
requests==2.25.0
Flask>=2.0
django ==3.2.1
numpy~=1.20
scipy
-r other.txt
git+https://github.com/example/example.git
`)

	var results checker.StaleDependenciesData
	if _, err := parsePinnedPythonRequirements("requirements.txt", content, &results); err != nil {
		t.Fatalf("parsePinnedPythonRequirements: %v", err)
	}

	// Only "==" pins are in scope: ranges resolve to the newest match, so
	// staleness would not be the manifest's doing.
	want := map[string]string{"requests": "2.25.0", "django": "3.2.1"}
	if len(results.Dependencies) != len(want) {
		t.Fatalf("got %d pins, want %d: %+v", len(results.Dependencies), len(want), results.Dependencies)
	}
	for _, d := range results.Dependencies {
		version, ok := want[d.Name]
		if !ok {
			t.Errorf("unexpected dependency %q collected", d.Name)
			continue
		}
		if d.PinnedVersion != version {
			t.Errorf("%s: got version %q, want %q", d.Name, d.PinnedVersion, version)
		}
		if d.Ecosystem != ecosystemPyPI {
			t.Errorf("%s: got ecosystem %q, want %q", d.Name, d.Ecosystem, ecosystemPyPI)
		}
	}
}

func TestParsePinnedPackageJSON(t *testing.T) {
	t.Parallel()
	content := []byte(`{
		"dependencies": {
			"exact-pkg": "1.2.3",
			"caret-pkg": "^1.2.3",
			"tilde-pkg": "~1.2.3",
			"range-pkg": ">=1.2.3",
			"wildcard-pkg": "1.x",
			"star-pkg": "*",
			"local-pkg": "file:../local",
			"prerelease-pkg": "2.0.0-beta.1"
		},
		"devDependencies": {
			"exact-dev": "4.5.6"
		}
	}`)

	var results checker.StaleDependenciesData
	if _, err := parsePinnedPackageJSON("package.json", content, &results); err != nil {
		t.Fatalf("parsePinnedPackageJSON: %v", err)
	}

	got := map[string]string{}
	for _, d := range results.Dependencies {
		got[d.Name] = d.PinnedVersion
		if d.Ecosystem != ecosystemNpm {
			t.Errorf("%s: got ecosystem %q, want %q", d.Name, d.Ecosystem, ecosystemNpm)
		}
	}

	for name, version := range map[string]string{
		"exact-pkg": "1.2.3", "exact-dev": "4.5.6", "prerelease-pkg": "2.0.0-beta.1",
	} {
		if got[name] != version {
			t.Errorf("expected %q pinned at %q, got %q", name, version, got[name])
		}
	}
	for _, name := range []string{"caret-pkg", "tilde-pkg", "range-pkg", "wildcard-pkg", "star-pkg", "local-pkg"} {
		if _, ok := got[name]; ok {
			t.Errorf("%q is not an exact pin and must not be collected", name)
		}
	}
}

func TestApplyStaleness(t *testing.T) {
	t.Parallel()

	now := time.Now()
	meta := &versionMetadata{
		LatestVersion: "2.0.0",
		ReleaseDates: map[string]time.Time{
			"1.0.0": now.AddDate(-3, 0, 0),
			"1.5.0": now.AddDate(-2, 0, 0),
			"1.9.0": now.AddDate(-1, 0, 0),
			"2.0.0": now,
		},
	}

	t.Run("old pin is measured in days and releases behind", func(t *testing.T) {
		t.Parallel()
		d := &checker.StaleDependency{PinnedVersion: "1.0.0"}
		applyStaleness(d, meta)
		if d.Error != nil {
			t.Fatalf("unexpected error: %v", *d.Error)
		}
		if d.LatestVersion != "2.0.0" {
			t.Errorf("got latest %q, want 2.0.0", d.LatestVersion)
		}
		// Three years, allowing for leap days.
		if d.DaysBehind < 1090 || d.DaysBehind > 1100 {
			t.Errorf("got %d days behind, want ~1095", d.DaysBehind)
		}
		if d.VersionsBehind != 3 {
			t.Errorf("got %d versions behind, want 3", d.VersionsBehind)
		}
	})

	t.Run("pin at latest is not stale", func(t *testing.T) {
		t.Parallel()
		d := &checker.StaleDependency{PinnedVersion: "2.0.0"}
		applyStaleness(d, meta)
		if d.DaysBehind != 0 || d.VersionsBehind != 0 {
			t.Errorf("latest pin should be 0/0, got %d days / %d versions", d.DaysBehind, d.VersionsBehind)
		}
	})

	t.Run("version absent from registry is an error, not maximal staleness", func(t *testing.T) {
		t.Parallel()
		// A yanked, renamed or private version must not be scored as though
		// the project were maximally out of date.
		d := &checker.StaleDependency{PinnedVersion: "9.9.9"}
		applyStaleness(d, meta)
		if d.Error == nil {
			t.Fatal("expected an error for a version absent from the registry")
		}
		if d.DaysBehind != 0 {
			t.Errorf("an undetermined pin must not report staleness, got %d days", d.DaysBehind)
		}
	})

	t.Run("nil metadata is an error", func(t *testing.T) {
		t.Parallel()
		d := &checker.StaleDependency{PinnedVersion: "1.0.0"}
		applyStaleness(d, nil)
		if d.Error == nil {
			t.Fatal("expected an error for nil metadata")
		}
	})
}

func TestResolveStalenessDedupesAndRecordsErrors(t *testing.T) {
	t.Parallel()

	now := time.Now()
	errLookup := errors.New("registry unreachable")
	calls := 0
	fetch := func(ecosystem, name string) (*versionMetadata, error) {
		calls++
		if name == "flaky" {
			return nil, errLookup
		}
		return &versionMetadata{
			LatestVersion: "2.0.0",
			ReleaseDates: map[string]time.Time{
				"1.0.0": now.AddDate(-2, 0, 0),
				"2.0.0": now,
			},
		}, nil
	}

	results := checker.StaleDependenciesData{
		Dependencies: []checker.StaleDependency{
			{Name: "pkg", Ecosystem: ecosystemPyPI, PinnedVersion: "1.0.0"},
			{Name: "flaky", Ecosystem: ecosystemPyPI, PinnedVersion: "1.0.0"},
			// Same package again: must be served from the per-run cache.
			{Name: "pkg", Ecosystem: ecosystemPyPI, PinnedVersion: "2.0.0"},
		},
	}

	resolveStaleness(&results, fetch)

	if calls != 2 {
		t.Errorf("expected 2 registry calls (pkg, flaky) with the repeat deduped, got %d", calls)
	}
	if results.Dependencies[0].DaysBehind < 700 {
		t.Errorf("first pin should be ~2 years behind, got %d", results.Dependencies[0].DaysBehind)
	}
	if results.Dependencies[1].Error == nil {
		t.Error("lookup failure should be recorded as an error")
	}
	if results.Dependencies[2].DaysBehind != 0 {
		t.Errorf("pin at latest should be current, got %d days behind", results.Dependencies[2].DaysBehind)
	}
}
