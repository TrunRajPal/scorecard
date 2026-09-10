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

// Detects INCOMPLETE SECRET REMEDIATION: a credential that no longer
// appears in the current tree but is still retrievable from git history,
// because it was "removed" in a later commit without rewriting history.
// Deleting a secret in a subsequent commit does not erase the historical
// blob -- anyone who can clone the repository can still recover it, so the
// credential remains exposed until it is rotated.
//
// Why this is the distinctive part of the check: detecting a credential
// sitting in the current tree is commodity functionality (gitleaks,
// trufflehog, GitHub secret scanning all do it well). Detecting that a
// remediation *attempt* was incomplete is different -- it measures whether
// the project's response to an exposure actually closed it.
//
// Evidence framing, stated honestly: the underlying failure mode is
// well-attested but is NOT specific to AI-generated code. Security
// researchers (CYPFER, reported by GitGuardian) found ~124,000 commits
// whose messages describe removing a credential while the credential
// remains recoverable one commit earlier -- but that figure does not
// separate AI-authored from human-authored commits, and the attribution of
// this pattern to AI assistants (Cursor, Claude Code, Codex) is qualitative
// rather than measured. The defensible claim is that AI assistants
// accelerate a long-standing human failure mode by committing at higher
// volume, not that they are uniquely responsible for it. Any write-up must
// not overstate this.
//
// ARCHITECTURAL CONSTRAINT: clients.RepoClient exposes no API for
// historical file content or diffs -- clients.Commit carries metadata only.
// History is therefore read via LocalPath() and go-git, following the
// precedent of raw/vulnerabilities.go using LocalPath(). Scorecard's
// default --file-mode archive fetches a tarball with no .git directory at
// all, so this half of the check cannot run there and reports
// HistoryAvailable=false rather than a misleading "no findings".

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
)

// maxHistoryCommits bounds the history walk. Diffing every commit of a
// long-lived repository is expensive and would make this check's runtime
// scale with project age. A credential buried deeper than this bound is
// not detected -- a stated limitation, surfaced via
// SecretHygieneData.CommitsScanned rather than hidden.
const maxHistoryCommits = 200

// maxHistoryFilePatches guards against a single enormous commit (a vendor
// import or generated-code dump) dominating the walk.
const maxHistoryFilePatches = 300

func collectHistorySecrets(
	c *checker.CheckRequest,
	results *checker.SecretHygieneData,
	headValues map[string]bool,
) error {
	localPath, err := c.RepoClient.LocalPath()
	if err != nil {
		// Not every client can provide a local path; treat as "history not
		// evaluated" rather than failing the whole check.
		return nil
	}

	repo, err := git.PlainOpen(localPath)
	if err != nil {
		// No .git present -- the expected outcome under the default
		// --file-mode archive (tarball) path. Explicitly not an error.
		if errors.Is(err, git.ErrRepositoryNotExists) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return nil
	}

	head, err := repo.Head()
	if err != nil {
		return nil // e.g. an empty repository.
	}

	commitIter, err := repo.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return fmt.Errorf("git log: %w", err)
	}
	defer commitIter.Close()

	results.HistoryAvailable = true

	// reported de-duplicates by detector+value+path so that a credential
	// surviving across many commits yields one finding, not one per commit.
	reported := make(map[string]bool)

	for i := 0; i < maxHistoryCommits; i++ {
		commit, err := commitIter.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// A malformed or unreachable object shouldn't fail the check.
			break
		}
		results.CommitsScanned++

		if err := scanCommitForRemovedSecrets(commit, headValues, reported, results); err != nil {
			continue
		}
	}

	return nil
}

// lineOfValueInCommitFile returns the 1-based line on which value appears
// in path as of commit, or 0 if it cannot be located. Called only when a
// credential has already been detected, so the extra blob read is on a
// rare path and does not affect the cost of scanning a clean repository.
//
// The caller passes a credential value here but nothing derived from it is
// returned or stored -- only a line number.
func lineOfValueInCommitFile(commit *object.Commit, path, value string) uint {
	file, err := commit.File(path)
	if err != nil {
		return 0
	}
	if file.Size > maxScannedFileSize {
		return 0
	}
	contents, err := file.Contents()
	if err != nil {
		return 0
	}
	for i, line := range strings.Split(contents, "\n") {
		if strings.Contains(line, value) {
			return uint(i + 1)
		}
	}
	return 0
}

// scanCommitForRemovedSecrets looks for credentials in lines this commit
// DELETED. A deleted credential that is absent from HEAD is an incomplete
// remediation: the removal commit exists, but the credential is still
// recoverable from this commit's parent.
func scanCommitForRemovedSecrets(
	commit *object.Commit,
	headValues map[string]bool,
	reported map[string]bool,
	results *checker.SecretHygieneData,
) error {
	// Root commits have no parent to diff against; a credential introduced
	// there and still present would be caught by the HEAD scan instead.
	if commit.NumParents() == 0 {
		return nil
	}
	parent, err := commit.Parent(0)
	if err != nil {
		return fmt.Errorf("commit.Parent: %w", err)
	}

	// Diff parent -> commit, so Delete chunks are content this commit
	// removed and which therefore still lives in the parent.
	patch, err := parent.Patch(commit)
	if err != nil {
		return fmt.Errorf("commit.Patch: %w", err)
	}

	filePatches := patch.FilePatches()
	if len(filePatches) > maxHistoryFilePatches {
		return nil
	}

	for _, fp := range filePatches {
		if fp.IsBinary() {
			continue
		}
		from, _ := fp.Files()
		if from == nil {
			continue // a newly added file has no removed content.
		}
		path := from.Path()
		// Same vendored/test/documentation exclusion as the current-tree
		// scan, so the two categories stay comparable: a difference between
		// them should reflect remediation behaviour, not differing filters.
		if fileIsInVendorDir(path) || isTemplatePath(path) || isNonProductionPath(path) {
			continue
		}

		for _, chunk := range fp.Chunks() {
			if chunk.Type() != diff.Delete {
				continue
			}
			for _, s := range scanForSecrets([]byte(chunk.Content())) {
				// Still in the current tree: that is an unremediated
				// exposure, already reported by the HEAD scan. Reporting it
				// here as well would double-count and conflate the two
				// categories.
				if headValues[s.Value] {
					continue
				}
				key := s.DetectorID + "\x00" + s.Value + "\x00" + path
				if reported[key] {
					continue
				}
				reported[key] = true

				results.Secrets = append(results.Secrets, checker.ExposedSecret{
					DetectorID: s.DetectorID,
					InHistory:  true,
					// The credential remains retrievable from the parent,
					// which is the commit that still holds it.
					CommitSHA: parent.Hash.String(),
					Location: &checker.File{
						Path: path,
						Type: finding.FileTypeSource,
						// Resolved against the parent commit's blob, so the
						// line refers to the historical file that still
						// contains the credential -- not to the current
						// tree, where it is absent. The probe's message
						// names the commit so this is not misread as a
						// current-tree location. Snippet stays empty: it
						// would carry the credential value.
						Offset: lineOfValueInCommitFile(parent, path, s.Value),
					},
				})
			}
		}
	}

	return nil
}
