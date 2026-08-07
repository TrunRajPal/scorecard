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

// SECRET HANDLING POLICY -- read before modifying this file.
//
// This check detects real, potentially live credentials in third-party
// repositories. Matched credential values are held in memory only for the
// duration of a single run (they are needed to correlate "was removed from
// HEAD" against "is still live in history"), and are NEVER written to
// checker.ExposedSecret, to findings, to log messages, or to any output.
// Only the detector ID, file location, and commit SHA are ever emitted.
// Do not add a field or log line that carries the matched value, a
// fingerprint of it, or enough surrounding context to reconstruct it.
//
// DETECTION SCOPE -- a deliberate precision-over-recall choice.
//
// Only high-confidence, structurally distinctive credential formats are
// matched (provider-prefixed tokens such as AKIA..., ghp_..., sk_live_...,
// and PEM private-key headers). Generic entropy- or keyword-based
// heuristics ("password = ...", high-Shannon-entropy strings) are
// deliberately NOT implemented: they are the dominant source of false
// positives in secret scanners, and this check is scored, so a false
// positive silently penalises a project's score. The cost of that choice
// is recall -- credentials in formats without a distinctive prefix
// (database URLs, generic API keys, bare high-entropy strings) are not
// detected. That is a stated limitation, not an oversight. Mature
// dedicated scanners (gitleaks, trufflehog, GitHub secret scanning) cover
// the broader surface; this check's contribution is the incomplete-
// remediation signal in secret_hygiene_history.go, not breadth of pattern
// coverage.

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks/fileparser"
	"github.com/ossf/scorecard/v5/finding"
)

// maxScannedFileSize bounds per-file work. Credentials live in source and
// config, not multi-megabyte assets, and unbounded scanning would make the
// check's runtime dependent on repository size.
const maxScannedFileSize = 1 << 20 // 1 MiB

// secretDetector is one high-confidence credential pattern.
type secretDetector struct {
	id string
	re *regexp.Regexp
}

// secretDetectors holds only provider-prefixed or otherwise structurally
// unambiguous formats -- see the DETECTION SCOPE note above.
var secretDetectors = []secretDetector{
	// AWS key IDs carry a fixed 4-character type prefix followed by 16
	// base32 characters.
	{"aws-access-key-id", regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)},
	{"github-personal-access-token", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
	{"github-fine-grained-token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{60,}\b`)},
	{"github-oauth-token", regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`)},
	{"github-app-token", regexp.MustCompile(`\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b`)},
	{"github-refresh-token", regexp.MustCompile(`\bghr_[A-Za-z0-9]{36}\b`)},
	{"gitlab-personal-access-token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20}\b`)},
	{"slack-token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"slack-webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+`)},
	{"stripe-live-secret-key", regexp.MustCompile(`\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b`)},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"npm-access-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"pypi-upload-token", regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`)},
	{"sendgrid-api-key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`)},
	{"openai-api-key", regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_\-]{20,}`)},
	{"anthropic-api-key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}`)},
	// Anchored to a line of its own. A real PEM blob puts the header on its
	// own line; an unanchored match also fires on source code that merely
	// *mentions* the header, e.g.
	//     if '-----BEGIN RSA PRIVATE KEY-----' in private_key_text:
	// which the negative-set run showed is a real and repeated false
	// positive. The cost is that a PEM key embedded inline in a JSON or
	// YAML string is not detected.
	{"private-key-pem", regexp.MustCompile(`^\s*-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----\s*$`)},
}

// detectorPrefilter holds a mandatory literal substring for every pattern
// in secretDetectors. A line containing none of these cannot match any
// detector, so this gate lets the common case (virtually every line of
// source in a repository) skip all 17 regex evaluations. Keep it in sync
// when adding a detector: each entry must be a substring that the
// corresponding regex always requires.
var detectorPrefilter = []string{
	"AKIA", "ASIA", "ABIA", "ACCA",
	"ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_",
	"glpat-", "xox", "hooks.slack.com",
	"sk_live_", "rk_live_", "AIza", "npm_", "pypi-", "SG.",
	"sk-proj-", "sk-ant-", "PRIVATE KEY",
}

// mayContainSecret is the cheap gate described on detectorPrefilter.
func mayContainSecret(line string) bool {
	for _, p := range detectorPrefilter {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

// placeholderMarkers appear in documentation and template values that
// match a real credential's shape but are not credentials. AWS's own
// documentation key (AKIA...EXAMPLE) is the canonical case.
var placeholderMarkers = []string{
	"example", "placeholder", "your-", "your_", "yourkey", "dummy",
	"sample", "changeme", "change-me", "replace", "redacted", "insert",
	"todo", "fixme", "xxxxx", "00000", "aaaaa", "12345", "notreal",
	"fake", "test-key", "testkey", "mykey", "abcdef",
}

// templatePathMarkers identify files whose entire purpose is to carry
// example values.
var templatePathMarkers = []string{
	".example", ".sample", ".template", ".dist", ".tpl",
}

// nonProductionDirSegments and nonProductionFileMarkers exclude files that
// are not the project's own shipped code: vendored dependencies, test
// fixtures, and documentation.
//
// This exclusion is empirically motivated, not defensive coding. An initial
// run of this check against 30 long-established repositories produced 18
// current-tree detections, of which 15 were vendored dependencies (Godeps/
// _workspace), test fixtures (server_test.go, a file literally named
// test_host_rsa_key_do_not_use), or documentation examples (docs/*.rst).
// Because a current-tree detection scores the minimum, those would have
// scored an established project 0/10 on the strength of a sample key in its
// own API documentation.
//
// The trade-off is explicit: a genuine credential committed inside a test
// fixture or documentation file is a real leak and this check will now miss
// it. That recall cost is accepted because the alternative -- a scored
// check that penalises projects for documentation samples -- is worse, and
// because dedicated secret scanners without a scoring mandate already cover
// the broader surface.
var nonProductionDirSegments = map[string]bool{
	"vendor": true, "third_party": true, "thirdparty": true,
	"godeps": true, "_workspace": true, "node_modules": true,
	"bower_components": true, "site-packages": true, ".venv": true, "venv": true,
	"docs": true, "doc": true,
	"test": true, "tests": true, "spec": true, "specs": true,
	"__tests__": true, "fixtures": true, "testdata": true,
	"example": true, "examples": true,
}

var nonProductionFileMarkers = []string{
	"_test.", ".test.", "_spec.", ".spec.", "do_not_use", "donotuse",
}

// isNonProductionPath reports whether a path is vendored, test, or
// documentation material -- see the note on nonProductionDirSegments.
func isNonProductionPath(pathfn string) bool {
	lower := strings.ToLower(filepath.ToSlash(pathfn))

	for _, segment := range strings.Split(lower, "/") {
		if nonProductionDirSegments[segment] {
			return true
		}
	}

	base := path.Base(lower)
	for _, marker := range nonProductionFileMarkers {
		if strings.Contains(base, marker) {
			return true
		}
	}
	if strings.HasPrefix(base, "test_") || strings.HasPrefix(base, "test-") {
		return true
	}
	// reStructuredText is essentially always documentation.
	return strings.HasSuffix(base, ".rst")
}

// isPlaceholder reports whether a matched value is a documentation or
// template stand-in rather than a plausible live credential.
func isPlaceholder(match string) bool {
	lower := strings.ToLower(match)
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// isTemplatePath reports whether a path is an example/template file.
func isTemplatePath(pathfn string) bool {
	lower := strings.ToLower(pathfn)
	for _, marker := range templatePathMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// looksBinary reports whether content should be skipped as non-text. A NUL
// byte in the first block is the conventional heuristic.
func looksBinary(content []byte) bool {
	head := content
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) != -1
}

// detectedSecret is an internal, in-memory-only match. The Value field is
// why this type is not exported and never reaches checker.ExposedSecret:
// it is used solely to correlate HEAD against history within one run.
type detectedSecret struct {
	DetectorID string
	Value      string
	Line       uint
}

// scanForSecrets applies every detector to content and returns matches,
// filtering out placeholders. Callers must not persist Value.
func scanForSecrets(content []byte) []detectedSecret {
	if len(content) == 0 || len(content) > maxScannedFileSize || looksBinary(content) {
		return nil
	}

	var found []detectedSecret
	scanner := bufio.NewScanner(bytes.NewReader(content))
	// Long single-line files (minified bundles) would otherwise overflow
	// the scanner's default token limit.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := uint(0)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if !mayContainSecret(line) {
			continue
		}
		for i := range secretDetectors {
			d := &secretDetectors[i]
			for _, match := range d.re.FindAllString(line, -1) {
				if isPlaceholder(match) {
					continue
				}
				found = append(found, detectedSecret{
					DetectorID: d.id,
					Value:      match,
					Line:       lineNum,
				})
			}
		}
	}
	return found
}

// SecretHygiene checks for credentials exposed in a repository, reporting
// two distinct categories: credentials present in the current tree
// (unremediated exposure), and credentials absent from the current tree
// but still retrievable from git history (an incomplete remediation --
// removed from HEAD without rewriting history, so still exposed to anyone
// who clones the repository).
//
// The history half requires git history, which Scorecard's default
// --file-mode archive does not provide; see collectHistorySecrets.
func SecretHygiene(c *checker.CheckRequest) (checker.SecretHygieneData, error) {
	var results checker.SecretHygieneData

	// headValues carries matched credential values in memory only, so the
	// history walk can tell "still at HEAD" (an unremediated exposure,
	// already reported below) from "removed at HEAD but live in history"
	// (an incomplete remediation). Never persisted -- see the policy note
	// at the top of this file.
	headValues := make(map[string]bool)

	if err := collectHeadSecrets(c, &results, headValues); err != nil {
		return checker.SecretHygieneData{}, err
	}
	if err := collectHistorySecrets(c, &results, headValues); err != nil {
		return checker.SecretHygieneData{}, err
	}

	return results, nil
}

func collectHeadSecrets(
	c *checker.CheckRequest,
	results *checker.SecretHygieneData,
	headValues map[string]bool,
) error {
	return fileparser.OnMatchingFileContentDo(c.RepoClient, fileparser.PathMatcher{
		Pattern:       "*",
		CaseSensitive: false,
	}, scanHeadFile, results, headValues)
}

var scanHeadFile fileparser.DoWhileTrueOnFileContent = func(
	pathfn string,
	content []byte,
	args ...interface{},
) (bool, error) {
	if len(args) != 2 {
		return false, fmt.Errorf(
			"scanHeadFile requires exactly 2 arguments: got %v: %w", len(args), errInvalidArgLength)
	}
	results, ok := args[0].(*checker.SecretHygieneData)
	if !ok {
		return false, fmt.Errorf("%w: expected *checker.SecretHygieneData", errInvalidArgType)
	}
	headValues, ok := args[1].(map[string]bool)
	if !ok {
		return false, fmt.Errorf("%w: expected map[string]bool", errInvalidArgType)
	}

	if fileIsInVendorDir(pathfn) || isNonProductionPath(pathfn) {
		return true, nil
	}

	for _, s := range scanForSecrets(content) {
		// Record the value regardless of path, so that a credential
		// legitimately present in a template file is still recognised as
		// "present at HEAD" by the history walk and not double-reported
		// as an incomplete remediation.
		headValues[s.Value] = true
		if isTemplatePath(pathfn) {
			continue
		}
		results.Secrets = append(results.Secrets, checker.ExposedSecret{
			DetectorID: s.DetectorID,
			InHistory:  false,
			Location: &checker.File{
				Path:   pathfn,
				Type:   finding.FileTypeSource,
				Offset: s.Line,
				// Snippet is deliberately left empty: it would carry the
				// credential value into findings and logs.
			},
		})
	}

	return true, nil
}
