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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks/fileparser"
	"github.com/ossf/scorecard/v5/finding"
)

// This file covers the resolved dependency graph via lockfiles
// (package-lock.json, poetry.lock, Pipfile.lock), as opposed to
// hallucinated_dependencies.go's direct-manifest coverage
// (requirements*.txt, package.json).
//
// This is a deliberately different check, not just "more files" for the
// same one: a transient dependency is resolved automatically by the
// package manager from an already-published parent package's own
// metadata -- no human or AI typed that name into this project. A
// lockfile entry that fails to resolve indicates a lockfile-integrity
// problem (tampering, a hand-edited or corrupted lockfile, or an AI tool
// editing a lockfile directly), not hallucination in Spracklen et al.'s
// sense. Every checker.HallucinatedDependency produced by this file has
// Transient set to true, and callers (the probe, evaluation) must keep
// Transient and non-Transient findings in separate counts.
//
// Stated simplification: npm's hoisting behavior means a package's
// position in the lockfile tree does not reliably indicate whether it was
// declared directly or pulled in transiently -- a top-level
// node_modules/X entry could be either. Rather than build an unreliable
// heuristic, every entry found in a lockfile is treated as belonging to
// "the resolved graph" as a whole, a superset of what the direct-manifest
// parsers already cover.
//
// Not yet supported (deferred, not silently dropped): yarn.lock (a
// distinct format from npm's own lockfiles). Plain requirements.txt-only
// Python projects have no native lockfile; a project using bare
// `pip freeze` output already gets transient coverage implicitly, since
// freeze flattens the full resolved set into requirements.txt -- read by
// the existing direct-manifest parser. That is a partial existing
// mitigation for that specific case, not a gap requiring new code here.

func collectNpmLockfile(c *checker.CheckRequest, r *checker.HallucinatedDependenciesData) error {
	return fileparser.OnMatchingFileContentDo(c.RepoClient, fileparser.PathMatcher{
		Pattern:       "package-lock.json",
		CaseSensitive: false,
	}, parseNpmLockfile, r)
}

// npmLockV1 models lockfileVersion 1: a "dependencies" object, nested
// recursively -- a transient dependency appears inside its parent's own
// "dependencies" key.
type npmLockV1 struct {
	Dependencies map[string]npmLockV1Dep `json:"dependencies"`
}

type npmLockV1Dep struct {
	Version      string                  `json:"version"`
	Dependencies map[string]npmLockV1Dep `json:"dependencies"`
}

// npmLockV2 models lockfileVersion 2/3: a flat "packages" object keyed by
// node_modules path (e.g. "node_modules/lodash", or a nested path for a
// de-duplicated transient package). This is what current `npm install`
// produces.
type npmLockV2 struct {
	Packages map[string]json.RawMessage `json:"packages"`
}

var parseNpmLockfile fileparser.DoWhileTrueOnFileContent = func(
	pathfn string,
	content []byte,
	args ...interface{},
) (bool, error) {
	if len(args) != 1 {
		return false, fmt.Errorf(
			"parseNpmLockfile requires exactly 1 argument: got %v: %w", len(args), errInvalidArgLength)
	}
	r, ok := args[0].(*checker.HallucinatedDependenciesData)
	if !ok {
		return false, fmt.Errorf("%w: expected *checker.HallucinatedDependenciesData", errInvalidArgType)
	}

	// Try v2/v3 "packages" format first -- this is what current npm produces.
	var v2 npmLockV2
	if err := json.Unmarshal(content, &v2); err == nil && len(v2.Packages) > 0 {
		seen := map[string]bool{}
		for path := range v2.Packages {
			if path == "" {
				continue // "" is the root project itself, not a dependency.
			}
			name := lastNodeModulesSegment(path)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			r.Dependencies = append(r.Dependencies, checker.HallucinatedDependency{
				Name:      name,
				Ecosystem: ecosystemNpm,
				Transient: true,
				Location: &checker.File{
					Path:    pathfn,
					Type:    finding.FileTypeSource,
					Offset:  lineNumberOf(content, path),
					Snippet: path,
				},
			})
		}
		if len(r.Dependencies) > 0 {
			return true, nil
		}
	}

	// Fall back to v1 nested "dependencies" format.
	var v1 npmLockV1
	if err := json.Unmarshal(content, &v1); err != nil {
		// Malformed package-lock.json isn't this check's concern; skip it.
		return true, nil
	}
	seen := map[string]bool{}
	var walk func(m map[string]npmLockV1Dep)
	walk = func(m map[string]npmLockV1Dep) {
		for name, entry := range m {
			if !seen[name] {
				seen[name] = true
				r.Dependencies = append(r.Dependencies, checker.HallucinatedDependency{
					Name:      name,
					Ecosystem: ecosystemNpm,
					Transient: true,
					Location: &checker.File{
						Path:    pathfn,
						Type:    finding.FileTypeSource,
						Offset:  lineNumberOf(content, name),
						Snippet: name + "@" + entry.Version,
					},
				})
			}
			if entry.Dependencies != nil {
				walk(entry.Dependencies)
			}
		}
	}
	walk(v1.Dependencies)

	return true, nil
}

// lastNodeModulesSegment extracts the package name from a
// package-lock.json v2/v3 "packages" key, e.g. "node_modules/lodash" ->
// "lodash", "node_modules/foo/node_modules/@scope/bar" -> "@scope/bar".
func lastNodeModulesSegment(path string) string {
	idx := strings.LastIndex(path, "node_modules/")
	if idx == -1 {
		return ""
	}
	return path[idx+len("node_modules/"):]
}

func collectPoetryLock(c *checker.CheckRequest, r *checker.HallucinatedDependenciesData) error {
	return fileparser.OnMatchingFileContentDo(c.RepoClient, fileparser.PathMatcher{
		Pattern:       "poetry.lock",
		CaseSensitive: false,
	}, parsePoetryLock, r)
}

// parsePoetryLock reads poetry.lock, which is TOML, but whose structure is
// simple and regular enough (flat key = "value" lines inside repeated
// [[package]] tables) that a small line-based scanner is used instead of a
// TOML library.
var parsePoetryLock fileparser.DoWhileTrueOnFileContent = func(
	pathfn string,
	content []byte,
	args ...interface{},
) (bool, error) {
	if len(args) != 1 {
		return false, fmt.Errorf(
			"parsePoetryLock requires exactly 1 argument: got %v: %w", len(args), errInvalidArgLength)
	}
	r, ok := args[0].(*checker.HallucinatedDependenciesData)
	if !ok {
		return false, fmt.Errorf("%w: expected *checker.HallucinatedDependenciesData", errInvalidArgType)
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := uint(0)
	inPackageBlock := false
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			inPackageBlock = true
			continue
		}
		if strings.HasPrefix(line, "[") && line != "[[package]]" {
			inPackageBlock = false // entered a different table, e.g. [package.dependencies] or [metadata].
		}
		if inPackageBlock && strings.HasPrefix(line, "name") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.Trim(strings.TrimSpace(parts[1]), `"`)
			if name == "" {
				continue
			}
			r.Dependencies = append(r.Dependencies, checker.HallucinatedDependency{
				Name:      normalizePyPIName(name),
				Ecosystem: ecosystemPyPI,
				Transient: true,
				Location: &checker.File{
					Path:    pathfn,
					Type:    finding.FileTypeSource,
					Offset:  lineNum,
					Snippet: line,
				},
			})
		}
	}

	return true, nil
}

func collectPipfileLock(c *checker.CheckRequest, r *checker.HallucinatedDependenciesData) error {
	return fileparser.OnMatchingFileContentDo(c.RepoClient, fileparser.PathMatcher{
		Pattern:       "Pipfile.lock",
		CaseSensitive: false,
	}, parsePipfileLock, r)
}

// pipfileLock models Pipfile.lock's "default" (runtime) and "develop"
// (dev) sections, each already containing the fully resolved set for that
// group.
type pipfileLock struct {
	Default map[string]json.RawMessage `json:"default"`
	Develop map[string]json.RawMessage `json:"develop"`
}

var parsePipfileLock fileparser.DoWhileTrueOnFileContent = func(
	pathfn string,
	content []byte,
	args ...interface{},
) (bool, error) {
	if len(args) != 1 {
		return false, fmt.Errorf(
			"parsePipfileLock requires exactly 1 argument: got %v: %w", len(args), errInvalidArgLength)
	}
	r, ok := args[0].(*checker.HallucinatedDependenciesData)
	if !ok {
		return false, fmt.Errorf("%w: expected *checker.HallucinatedDependenciesData", errInvalidArgType)
	}

	var pf pipfileLock
	if err := json.Unmarshal(content, &pf); err != nil {
		// Malformed Pipfile.lock isn't this check's concern; skip it.
		return true, nil
	}

	addPipfileLockDeps := func(m map[string]json.RawMessage) {
		for name := range m {
			r.Dependencies = append(r.Dependencies, checker.HallucinatedDependency{
				Name:      normalizePyPIName(name),
				Ecosystem: ecosystemPyPI,
				Transient: true,
				Location: &checker.File{
					Path:    pathfn,
					Type:    finding.FileTypeSource,
					Offset:  lineNumberOf(content, name),
					Snippet: name,
				},
			})
		}
	}
	addPipfileLockDeps(pf.Default)
	addPipfileLockDeps(pf.Develop)

	return true, nil
}
