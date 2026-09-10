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

// ---------------------------------------------------------------------------
// CONTRIBUTED WORK. Written for the ELE8095 Individual Research Project
// (DC03), Queen's University Belfast: "Extending Open-Source Software
// Security Metrics for AI-Generated Code". Author: Trun Raj Pal, 40498374.
//
// Not part of upstream github.com/ossf/scorecard. Any file in this
// repository without this notice is upstream code by the OpenSSF Scorecard
// Authors, used under the Apache 2.0 licence above.
// ---------------------------------------------------------------------------

package raw

// Measures how far behind the newest release each exactly-pinned direct
// dependency is, in both elapsed time and number of intervening releases.
//
// WHY THIS IS NOT COVERED BY EXISTING CHECKS. Scorecard's Vulnerabilities
// check reports dependencies with a *known* CVE; a dependency three years
// out of date with no CVE assigned yet is invisible to it. Pinned-
// Dependencies concerns whether a dependency is pinned by hash, not how old
// the pinned version is -- a hash-pinned 2019 release scores perfectly.
// Dependency-Update-Tool reports whether Dependabot or Renovate is
// configured, which is a process signal rather than a statement about the
// dependencies themselves. Staleness is a *leading* indicator of risk;
// known-vulnerability is a *lagging* one, and Scorecard currently has only
// the lagging indicator.
//
// EVIDENCE, AND WHAT IT DOES NOT SAY. Singla et al. (arXiv:2601.00205,
// 117,062 dependency changes) found AI agents select known-vulnerable
// dependency versions more often than humans (2.46% vs 1.64%), and that
// agent-selected vulnerable versions required a *major*-version upgrade to
// reach a patch 36.8% of the time versus 12.9% for humans -- i.e. agents
// pick versions that are further behind. That is measured, direct
// agent-versus-human evidence.
//
// It does NOT establish the mechanism. The paper does not attribute this to
// model training cutoffs, and does not measure version age at all. The
// project brief's phrase "stale relative to a model's training cutoff"
// therefore names a hypothesis, not a finding. This check measures a
// condition and must not be described as detecting AI authorship: a stale
// pin is frequently deliberate, arising from compatibility constraints,
// stability policies, or platform limits.
//
// SCOPE. Only *exact* pins in *direct* manifests are assessed. A version
// range such as "^1.2.3" resolves to the newest matching release, so
// staleness is not the manifest's doing. Transitive dependencies are
// excluded because a maintainer cannot change them directly, and because a
// manifest pin is where a human or an AI made a decision -- the same
// reasoning applied throughout this project.

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

// exactPinRe matches a requirements.txt line pinning an exact version with
// "==". Range and compatible-release operators (>=, ~=, <, !=) are
// deliberately not matched -- see the SCOPE note above.
var exactPinRe = regexp.MustCompile(`^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)`)

// npmExactVersionRe matches a package.json dependency value that is an
// exact version rather than a range: "1.2.3" or "1.2.3-beta.1", but not
// "^1.2.3", "~1.2.3", ">=1.2.3", "1.x" or "*".
var npmExactVersionRe = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.\-]+)?$`)

// StaleDependencies measures how far behind the newest release each
// exactly-pinned direct dependency is.
func StaleDependencies(c *checker.CheckRequest) (checker.StaleDependenciesData, error) {
	var results checker.StaleDependenciesData

	if err := collectPinnedPythonRequirements(c, &results); err != nil {
		return checker.StaleDependenciesData{}, err
	}
	if err := collectPinnedPackageJSON(c, &results); err != nil {
		return checker.StaleDependenciesData{}, err
	}

	resolveStaleness(&results, fetchVersionMetadata)

	return results, nil
}

func collectPinnedPythonRequirements(c *checker.CheckRequest, r *checker.StaleDependenciesData) error {
	return fileparser.OnMatchingFileContentDo(c.RepoClient, fileparser.PathMatcher{
		Pattern:       "requirements*.txt",
		CaseSensitive: false,
	}, parsePinnedPythonRequirements, r)
}

var parsePinnedPythonRequirements fileparser.DoWhileTrueOnFileContent = func(
	pathfn string,
	content []byte,
	args ...interface{},
) (bool, error) {
	if len(args) != 1 {
		return false, fmt.Errorf(
			"parsePinnedPythonRequirements requires exactly 1 argument: got %v: %w",
			len(args), errInvalidArgLength)
	}
	r, ok := args[0].(*checker.StaleDependenciesData)
	if !ok {
		return false, fmt.Errorf("%w: expected *checker.StaleDependenciesData", errInvalidArgType)
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := uint(0)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "-") || strings.Contains(line, "://") {
			continue
		}
		match := exactPinRe.FindStringSubmatch(line)
		if match == nil {
			continue // a range, not an exact pin.
		}
		name := normalizePyPIName(match[1])
		if name == "" {
			continue
		}
		r.Dependencies = append(r.Dependencies, checker.StaleDependency{
			Name:          name,
			Ecosystem:     ecosystemPyPI,
			PinnedVersion: match[2],
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

func collectPinnedPackageJSON(c *checker.CheckRequest, r *checker.StaleDependenciesData) error {
	return fileparser.OnMatchingFileContentDo(c.RepoClient, fileparser.PathMatcher{
		Pattern:       "package.json",
		CaseSensitive: false,
	}, parsePinnedPackageJSON, r)
}

var parsePinnedPackageJSON fileparser.DoWhileTrueOnFileContent = func(
	pathfn string,
	content []byte,
	args ...interface{},
) (bool, error) {
	if len(args) != 1 {
		return false, fmt.Errorf(
			"parsePinnedPackageJSON requires exactly 1 argument: got %v: %w",
			len(args), errInvalidArgLength)
	}
	r, ok := args[0].(*checker.StaleDependenciesData)
	if !ok {
		return false, fmt.Errorf("%w: expected *checker.StaleDependenciesData", errInvalidArgType)
	}

	var pkg packageJSON
	if err := json.Unmarshal(content, &pkg); err != nil {
		// Malformed package.json isn't this check's concern; skip it.
		return true, nil
	}

	add := func(deps map[string]string) {
		for name, version := range deps {
			if !npmExactVersionRe.MatchString(version) {
				continue // a range, or a file:/git:/workspace: reference.
			}
			r.Dependencies = append(r.Dependencies, checker.StaleDependency{
				Name:          name,
				Ecosystem:     ecosystemNpm,
				PinnedVersion: version,
				Location: &checker.File{
					Path:    pathfn,
					Type:    finding.FileTypeSource,
					Offset:  lineNumberOf(content, name),
					Snippet: name + "@" + version,
				},
			})
		}
	}
	add(pkg.Dependencies)
	add(pkg.DevDependencies)

	return true, nil
}

// versionMetadata is what the staleness calculation needs from a registry:
// the newest version, and the release date of every version.
type versionMetadata struct {
	LatestVersion string
	// ReleaseDates maps version string to publication time.
	ReleaseDates map[string]time.Time
}

// metadataFetcher retrieves version metadata for a package. A function
// value so tests can substitute a fake and avoid live network calls.
type metadataFetcher func(ecosystem, name string) (*versionMetadata, error)

// resolveStaleness fills in staleness for every collected dependency,
// deduplicating registry calls by ecosystem+name within a run.
func resolveStaleness(r *checker.StaleDependenciesData, fetch metadataFetcher) {
	type cached struct {
		meta *versionMetadata
		err  error
	}
	cache := map[string]cached{}

	for i := range r.Dependencies {
		d := &r.Dependencies[i]
		key := d.Ecosystem + ":" + d.Name

		got, ok := cache[key]
		if !ok {
			meta, err := fetch(d.Ecosystem, d.Name)
			got = cached{meta: meta, err: err}
			cache[key] = got
		}

		if got.err != nil {
			msg := got.err.Error()
			d.Error = &msg
			continue
		}
		applyStaleness(d, got.meta)
	}
}

// applyStaleness computes how far behind a pin is. A pinned version absent
// from the registry is recorded as an error rather than as maximal
// staleness: it may have been yanked, or be a private or renamed package,
// and none of those is evidence that the project is out of date.
func applyStaleness(d *checker.StaleDependency, meta *versionMetadata) {
	if meta == nil {
		msg := "no version metadata available"
		d.Error = &msg
		return
	}

	d.LatestVersion = meta.LatestVersion

	pinnedDate, ok := meta.ReleaseDates[d.PinnedVersion]
	if !ok {
		msg := fmt.Sprintf("pinned version %q not found on the registry", d.PinnedVersion)
		d.Error = &msg
		return
	}

	latestDate, ok := meta.ReleaseDates[meta.LatestVersion]
	if !ok {
		// Fall back to the newest date seen, so an unusual dist-tag doesn't
		// prevent a measurement.
		for _, t := range meta.ReleaseDates {
			if t.After(latestDate) {
				latestDate = t
			}
		}
	}

	if latestDate.After(pinnedDate) {
		d.DaysBehind = int(latestDate.Sub(pinnedDate).Hours() / 24)
	}
	for _, t := range meta.ReleaseDates {
		if t.After(pinnedDate) {
			d.VersionsBehind++
		}
	}
}

func fetchVersionMetadata(ecosystem, name string) (*versionMetadata, error) {
	switch ecosystem {
	case ecosystemPyPI:
		return fetchPyPIMetadata(name)
	case ecosystemNpm:
		return fetchNpmMetadata(name)
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedEcosystem, ecosystem)
	}
}

// pypiMetadataDoc models the subset of PyPI's JSON API this check needs.
type pypiMetadataDoc struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	Releases map[string][]struct {
		UploadTime string `json:"upload_time_iso_8601"`
	} `json:"releases"`
}

func fetchPyPIMetadata(name string) (*versionMetadata, error) {
	endpoint := fmt.Sprintf("https://pypi.org/pypi/%s/json", url.PathEscape(name))
	resp, err := registryHTTPClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("pypi metadata for %q: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi metadata for %q: unexpected status %d", name, resp.StatusCode)
	}

	var doc pypiMetadataDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("pypi metadata for %q: decoding response: %w", name, err)
	}

	meta := &versionMetadata{
		LatestVersion: doc.Info.Version,
		ReleaseDates:  make(map[string]time.Time, len(doc.Releases)),
	}
	for version, files := range doc.Releases {
		// A version with no files (fully yanked) has no usable date.
		if len(files) == 0 {
			continue
		}
		t, err := time.Parse(time.RFC3339, files[0].UploadTime)
		if err != nil {
			continue
		}
		meta.ReleaseDates[version] = t
	}
	return meta, nil
}

// npmMetadataDoc models the subset of the npm registry document this check
// needs. The "time" object maps every published version to its publish
// date, alongside the non-version keys "created" and "modified".
type npmMetadataDoc struct {
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
	Time map[string]string `json:"time"`
}

func fetchNpmMetadata(name string) (*versionMetadata, error) {
	endpoint := fmt.Sprintf("https://registry.npmjs.org/%s", url.PathEscape(name))
	resp, err := registryHTTPClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("npm metadata for %q: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm metadata for %q: unexpected status %d", name, resp.StatusCode)
	}

	var doc npmMetadataDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("npm metadata for %q: decoding response: %w", name, err)
	}

	meta := &versionMetadata{
		LatestVersion: doc.DistTags.Latest,
		ReleaseDates:  make(map[string]time.Time, len(doc.Time)),
	}
	for version, raw := range doc.Time {
		if version == "created" || version == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			continue
		}
		meta.ReleaseDates[version] = t
	}
	return meta, nil
}
