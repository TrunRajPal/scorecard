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
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks/fileparser"
	"github.com/ossf/scorecard/v5/finding"
)

const (
	ecosystemPyPI = "pypi"
	ecosystemNpm  = "npm"
)

// requirementLineRe strips version specifiers, extras, environment markers,
// and inline comments from a requirements.txt line, leaving the bare
// package name. This intentionally does NOT try to parse import statements
// -- Spracklen et al. (USENIX Sec'25, Appendix G) note that import/module
// names do not map 1:1 onto package names, so parsing manifests directly is
// the more reliable ground truth for "what will actually be installed".
var requirementLineRe = regexp.MustCompile(`^\s*([A-Za-z0-9_.\-]+)`)

var pypiNormalizeRe = regexp.MustCompile(`[-_.]+`)

// registryHTTPClient is shared across lookups with a sane timeout --
// registry lookups run per-dependency, so a hung request shouldn't stall
// the whole check.
var registryHTTPClient = &http.Client{Timeout: 10 * time.Second}

// HallucinatedDependencies checks both direct dependency manifests
// (requirements*.txt, package.json) and lockfiles (package-lock.json,
// poetry.lock, Pipfile.lock) for packages that don't exist on their
// ecosystem's public registry. A direct-manifest entry that doesn't exist
// is evidence of an AI-hallucinated package name (Spracklen et al., USENIX
// Sec'25: up to 21.7% of AI-recommended packages didn't exist); a
// lockfile entry that doesn't exist is a different failure mode --
// evidence of lockfile-integrity issues, not hallucination -- see
// checker.HallucinatedDependency.Transient and
// hallucinated_dependencies_lockfile.go.
func HallucinatedDependencies(c *checker.CheckRequest) (checker.HallucinatedDependenciesData, error) {
	var results checker.HallucinatedDependenciesData

	if err := collectPythonRequirements(c, &results); err != nil {
		return checker.HallucinatedDependenciesData{}, err
	}
	if err := collectPackageJSON(c, &results); err != nil {
		return checker.HallucinatedDependenciesData{}, err
	}
	if err := collectNpmLockfile(c, &results); err != nil {
		return checker.HallucinatedDependenciesData{}, err
	}
	if err := collectPoetryLock(c, &results); err != nil {
		return checker.HallucinatedDependenciesData{}, err
	}
	if err := collectPipfileLock(c, &results); err != nil {
		return checker.HallucinatedDependenciesData{}, err
	}

	cache := loadRegistryCache()
	resolveExistence(&results, cachingExistenceChecker(cache, checkRegistryExistence))
	cache.save()

	return results, nil
}

func collectPythonRequirements(c *checker.CheckRequest, r *checker.HallucinatedDependenciesData) error {
	return fileparser.OnMatchingFileContentDo(c.RepoClient, fileparser.PathMatcher{
		Pattern:       "requirements*.txt",
		CaseSensitive: false,
	}, parsePythonRequirements, r)
}

var parsePythonRequirements fileparser.DoWhileTrueOnFileContent = func(
	pathfn string,
	content []byte,
	args ...interface{},
) (bool, error) {
	if len(args) != 1 {
		return false, fmt.Errorf(
			"parsePythonRequirements requires exactly 1 argument: got %v: %w", len(args), errInvalidArgLength)
	}
	r, ok := args[0].(*checker.HallucinatedDependenciesData)
	if !ok {
		return false, fmt.Errorf("%w: expected *checker.HallucinatedDependenciesData", errInvalidArgType)
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := uint(0)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip options/flags (-r, -e, --index-url, etc.) and VCS/URL
		// installs, which don't reference the public package index by name.
		if strings.HasPrefix(line, "-") || strings.Contains(line, "://") {
			continue
		}
		match := requirementLineRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		name := normalizePyPIName(match[1])
		if name == "" {
			continue
		}
		r.Dependencies = append(r.Dependencies, checker.HallucinatedDependency{
			Name:      name,
			Ecosystem: ecosystemPyPI,
			Location: &checker.File{
				Path:    pathfn,
				Type:    finding.FileTypeSource,
				Offset:  lineNum,
				Snippet: line,
			},
		})
	}

	return true, nil
}

// normalizePyPIName applies PEP 503 normalization: lowercase, and runs of
// -_. collapsed to a single hyphen. This matters because a hallucinated
// name that merely differs in case/separator from a real package should
// NOT be flagged as non-existent -- it IS the real package, just spelled
// inconsistently, which is a separate (typosquat-adjacent) concern from
// hallucination.
func normalizePyPIName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return pypiNormalizeRe.ReplaceAllString(name, "-")
}

// packageJSON models the subset of package.json we care about.
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func collectPackageJSON(c *checker.CheckRequest, r *checker.HallucinatedDependenciesData) error {
	return fileparser.OnMatchingFileContentDo(c.RepoClient, fileparser.PathMatcher{
		Pattern:       "package.json",
		CaseSensitive: false,
	}, parsePackageJSON, r)
}

var parsePackageJSON fileparser.DoWhileTrueOnFileContent = func(
	pathfn string,
	content []byte,
	args ...interface{},
) (bool, error) {
	if len(args) != 1 {
		return false, fmt.Errorf(
			"parsePackageJSON requires exactly 1 argument: got %v: %w", len(args), errInvalidArgLength)
	}
	r, ok := args[0].(*checker.HallucinatedDependenciesData)
	if !ok {
		return false, fmt.Errorf("%w: expected *checker.HallucinatedDependenciesData", errInvalidArgType)
	}

	var pkg packageJSON
	if err := json.Unmarshal(content, &pkg); err != nil {
		// Malformed package.json isn't this check's concern; skip it.
		return true, nil
	}

	addPackageJSONDeps(pathfn, content, pkg.Dependencies, r)
	addPackageJSONDeps(pathfn, content, pkg.DevDependencies, r)

	return true, nil
}

func addPackageJSONDeps(pathfn string, content []byte, deps map[string]string, r *checker.HallucinatedDependenciesData) {
	for name, version := range deps {
		// Skip local/workspace/URL-based deps -- not registry lookups.
		if strings.HasPrefix(version, "file:") ||
			strings.HasPrefix(version, "git") ||
			strings.HasPrefix(version, "http") ||
			strings.HasPrefix(version, "workspace:") {
			continue
		}
		r.Dependencies = append(r.Dependencies, checker.HallucinatedDependency{
			Name:      name,
			Ecosystem: ecosystemNpm,
			Location: &checker.File{
				Path:    pathfn,
				Type:    finding.FileTypeSource,
				Offset:  lineNumberOf(content, name),
				Snippet: name + "@" + version,
			},
		})
	}
}

// lineNumberOf returns the 1-based line on which name first appears as a
// quoted JSON key/value, or 0 if not found. This is a best-effort location
// for display purposes; it does not need to disambiguate identically-named
// keys appearing in both dependencies and devDependencies.
func lineNumberOf(content []byte, name string) uint {
	idx := bytes.Index(content, []byte(`"`+name+`"`))
	if idx < 0 {
		return 0
	}
	return uint(bytes.Count(content[:idx], []byte("\n")) + 1)
}

// existenceChecker reports whether a package currently resolves on the
// public registry for its ecosystem. It's a function value (rather than a
// direct call) so tests can substitute a fake and avoid live network calls.
type existenceChecker func(ecosystem, name string) (bool, error)

// resolveExistence runs registry existence checks for all collected
// dependencies, deduplicating lookups by ecosystem+name -- the same
// package can appear in multiple manifests, and hitting the registry once
// per unique name keeps this feasible at repo scale.
func resolveExistence(r *checker.HallucinatedDependenciesData, check existenceChecker) {
	type lookupResult struct {
		exists *bool
		errMsg *string
	}
	cache := map[string]lookupResult{}

	for i := range r.Dependencies {
		d := &r.Dependencies[i]
		cacheKey := d.Ecosystem + ":" + d.Name

		cached, ok := cache[cacheKey]
		if !ok {
			exists, err := check(d.Ecosystem, d.Name)
			if err != nil {
				msg := err.Error()
				cached = lookupResult{errMsg: &msg}
			} else {
				cached = lookupResult{exists: &exists}
			}
			cache[cacheKey] = cached
		}

		d.Exists = cached.exists
		d.Error = cached.errMsg
	}
}

func checkRegistryExistence(ecosystem, name string) (bool, error) {
	switch ecosystem {
	case ecosystemPyPI:
		return pypiExists(name)
	case ecosystemNpm:
		return npmExists(name)
	default:
		return false, fmt.Errorf("%w: %s", errUnsupportedEcosystem, ecosystem)
	}
}

func pypiExists(name string) (bool, error) {
	endpoint := fmt.Sprintf("https://pypi.org/pypi/%s/json", url.PathEscape(name))
	resp, err := registryHTTPClient.Get(endpoint)
	if err != nil {
		return false, fmt.Errorf("pypi lookup for %q: %w", name, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("pypi lookup for %q: unexpected status %d", name, resp.StatusCode)
	}
}

// npmPackageDoc is used only to confirm the response is a real package
// document rather than an error body -- we don't need its fields beyond
// existence, but decoding guards against false positives from registries
// that return 200 with an error payload.
type npmPackageDoc struct {
	Name string `json:"name"`
}

func npmExists(name string) (bool, error) {
	// npm scoped packages (@scope/name) must have the '/' percent-encoded
	// as %2f in the registry URL path.
	endpoint := fmt.Sprintf("https://registry.npmjs.org/%s", url.PathEscape(name))
	resp, err := registryHTTPClient.Get(endpoint)
	if err != nil {
		return false, fmt.Errorf("npm lookup for %q: %w", name, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var doc npmPackageDoc
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			return false, fmt.Errorf("npm lookup for %q: decoding response: %w", name, err)
		}
		return doc.Name != "", nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("npm lookup for %q: unexpected status %d", name, resp.StatusCode)
	}
}
