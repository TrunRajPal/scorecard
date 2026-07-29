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
	"testing"

	"github.com/ossf/scorecard/v5/checker"
)

func TestParseNpmLockfileV2V3(t *testing.T) {
	t.Parallel()
	content := []byte(`{
		"name": "test",
		"lockfileVersion": 3,
		"packages": {
			"": { "name": "test", "version": "1.0.0" },
			"node_modules/express": { "version": "4.18.2" },
			"node_modules/totally-fake-toplevel-pkg": { "version": "1.0.0" },
			"node_modules/express/node_modules/nested-fake-pkg": { "version": "2.0.0" },
			"node_modules/@scope/real-scoped-pkg": { "version": "1.0.0" }
		}
	}`)

	var results checker.HallucinatedDependenciesData
	if _, err := parseNpmLockfile("package-lock.json", content, &results); err != nil {
		t.Fatalf("parseNpmLockfile: %v", err)
	}

	got := map[string]bool{}
	for _, d := range results.Dependencies {
		got[d.Name] = true
		if d.Ecosystem != ecosystemNpm {
			t.Errorf("dependency %q: got ecosystem %q, want %q", d.Name, d.Ecosystem, ecosystemNpm)
		}
		if !d.Transient {
			t.Errorf("dependency %q: expected Transient=true for a lockfile entry", d.Name)
		}
	}

	want := []string{"express", "totally-fake-toplevel-pkg", "nested-fake-pkg", "@scope/real-scoped-pkg"}
	for _, name := range want {
		if !got[name] {
			t.Errorf("expected dependency %q to be collected, got %+v", name, got)
		}
	}
	if got[""] {
		t.Errorf("the root project entry (empty packages key) must not be collected as a dependency")
	}
	if len(results.Dependencies) != len(want) {
		t.Errorf("got %d dependencies, want %d: %+v", len(results.Dependencies), len(want), results.Dependencies)
	}
}

func TestParseNpmLockfileV1(t *testing.T) {
	t.Parallel()
	content := []byte(`{
		"name": "test",
		"lockfileVersion": 1,
		"dependencies": {
			"express": {
				"version": "4.18.2",
				"dependencies": {
					"totally-fake-nested-v1-pkg": { "version": "1.0.0" }
				}
			},
			"lodash": { "version": "4.17.21" }
		}
	}`)

	var results checker.HallucinatedDependenciesData
	if _, err := parseNpmLockfile("package-lock.json", content, &results); err != nil {
		t.Fatalf("parseNpmLockfile: %v", err)
	}

	got := map[string]bool{}
	for _, d := range results.Dependencies {
		got[d.Name] = true
		if !d.Transient {
			t.Errorf("dependency %q: expected Transient=true for a lockfile entry", d.Name)
		}
	}

	for _, name := range []string{"express", "lodash", "totally-fake-nested-v1-pkg"} {
		if !got[name] {
			t.Errorf("expected dependency %q to be collected (nested v1 dependency), got %+v", name, got)
		}
	}
}

func TestParseNpmLockfileMalformed(t *testing.T) {
	t.Parallel()
	var results checker.HallucinatedDependenciesData
	cont, err := parseNpmLockfile("package-lock.json", []byte("not valid json"), &results)
	if err != nil {
		t.Fatalf("parseNpmLockfile should not error on malformed content, got: %v", err)
	}
	if !cont {
		t.Errorf("parseNpmLockfile should continue iterating (return true) even on malformed content")
	}
	if len(results.Dependencies) != 0 {
		t.Errorf("expected no dependencies from malformed content, got %+v", results.Dependencies)
	}
}

func TestLastNodeModulesSegment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path string
		want string
	}{
		{"node_modules/lodash", "lodash"},
		{"node_modules/foo/node_modules/@scope/bar", "@scope/bar"},
		{"node_modules/express/node_modules/nested-pkg", "nested-pkg"},
		{"", ""},
		{"src/index.js", ""},
	}
	for _, tt := range tests {
		if got := lastNodeModulesSegment(tt.path); got != tt.want {
			t.Errorf("lastNodeModulesSegment(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestParsePoetryLock(t *testing.T) {
	t.Parallel()
	content := []byte(`[[package]]
name = "requests"
version = "2.31.0"

[package.dependencies]
name = "should-not-be-collected-from-subtable"

[[package]]
name = "totally-fake-poetry-pkg"
version = "1.0.0"

[metadata]
lock-version = "2.0"
`)

	var results checker.HallucinatedDependenciesData
	if _, err := parsePoetryLock("poetry.lock", content, &results); err != nil {
		t.Fatalf("parsePoetryLock: %v", err)
	}

	got := map[string]bool{}
	for _, d := range results.Dependencies {
		got[d.Name] = true
		if d.Ecosystem != ecosystemPyPI {
			t.Errorf("dependency %q: got ecosystem %q, want %q", d.Name, d.Ecosystem, ecosystemPyPI)
		}
		if !d.Transient {
			t.Errorf("dependency %q: expected Transient=true for a lockfile entry", d.Name)
		}
	}

	if !got["requests"] || !got["totally-fake-poetry-pkg"] {
		t.Errorf("expected requests and totally-fake-poetry-pkg to be collected, got %+v", got)
	}
	if got["should-not-be-collected-from-subtable"] {
		t.Errorf("a name= line inside [package.dependencies] must not be collected -- it isn't a [[package]] block")
	}
	if len(results.Dependencies) != 2 {
		t.Errorf("got %d dependencies, want 2: %+v", len(results.Dependencies), results.Dependencies)
	}
}

func TestParsePipfileLock(t *testing.T) {
	t.Parallel()
	content := []byte(`{
		"default": {
			"flask": {"version": "==2.3.0"},
			"totally-fake-pipfile-default-pkg": {"version": "==1.0.0"}
		},
		"develop": {
			"pytest": {"version": "==7.4.0"}
		}
	}`)

	var results checker.HallucinatedDependenciesData
	if _, err := parsePipfileLock("Pipfile.lock", content, &results); err != nil {
		t.Fatalf("parsePipfileLock: %v", err)
	}

	got := map[string]bool{}
	for _, d := range results.Dependencies {
		got[d.Name] = true
		if d.Ecosystem != ecosystemPyPI {
			t.Errorf("dependency %q: got ecosystem %q, want %q", d.Name, d.Ecosystem, ecosystemPyPI)
		}
		if !d.Transient {
			t.Errorf("dependency %q: expected Transient=true for a lockfile entry", d.Name)
		}
	}

	for _, name := range []string{"flask", "totally-fake-pipfile-default-pkg", "pytest"} {
		if !got[name] {
			t.Errorf("expected dependency %q to be collected, got %+v", name, got)
		}
	}
	if len(results.Dependencies) != 3 {
		t.Errorf("got %d dependencies, want 3: %+v", len(results.Dependencies), results.Dependencies)
	}
}

func TestParsePipfileLockMalformed(t *testing.T) {
	t.Parallel()
	var results checker.HallucinatedDependenciesData
	cont, err := parsePipfileLock("Pipfile.lock", []byte("not valid json"), &results)
	if err != nil {
		t.Fatalf("parsePipfileLock should not error on malformed content, got: %v", err)
	}
	if !cont {
		t.Errorf("parsePipfileLock should continue iterating (return true) even on malformed content")
	}
	if len(results.Dependencies) != 0 {
		t.Errorf("expected no dependencies from malformed content, got %+v", results.Dependencies)
	}
}
