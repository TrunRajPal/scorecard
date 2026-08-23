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

// Tests for the incomplete-remediation half of Secret-Hygiene: a credential
// deleted from the working tree that remains retrievable from history.
//
// This is the part of the check with no counterpart in Scorecard and no
// evaluation evidence of its own -- the deep-cloned corpus run produced zero
// detections, which bounds its false-positive rate but demonstrates nothing
// about whether it fires. These fixtures supply that missing half.
//
// Repositories are built in-process with go-git rather than committed as
// binary .git fixtures, so the tests carry no checked-in history of their own
// and do not depend on a developer's git configuration.
//
// FIXTURE VALUES: reuse the fx* constants from secret_hygiene_test.go. They
// are assembled from fragments at run time because GitHub push protection
// blocks these patterns when written as whole literals. Do not inline them.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"go.uber.org/mock/gomock"

	"github.com/ossf/scorecard/v5/checker"
	mockrepo "github.com/ossf/scorecard/v5/clients/mockclients"
)

// commitSpec is one commit: files to write (path -> content) and paths to
// delete. A path written in one commit and deleted in the next is the
// incomplete-remediation pattern the check exists to find.
type commitSpec struct {
	files   map[string]string
	deleted []string
}

// newHistoryFixture builds a real git repository in a temp directory and
// returns its path.
func newHistoryFixture(t *testing.T, commits []commitSpec) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("git init: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	for i, c := range commits {
		for path, content := range c.files {
			writeFixtureFile(t, dir, path, content)
			if _, err := wt.Add(path); err != nil {
				t.Fatalf("add %s: %v", path, err)
			}
		}
		for _, path := range c.deleted {
			if _, err := wt.Remove(path); err != nil {
				t.Fatalf("remove %s: %v", path, err)
			}
		}
		_, err := wt.Commit(commitMessage(i), &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Fixture",
				Email: "fixture@example.invalid",
				// Fixed, distinct timestamps keep the log order deterministic.
				When: time.Unix(int64(1700000000+i*60), 0).UTC(),
			},
			AllowEmptyCommits: true,
		})
		if err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	return dir
}

func commitMessage(i int) string {
	return "fixture commit " + string(rune('a'+i%26))
}

func writeFixtureFile(t *testing.T, dir, path, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// runHistory wires a fixture repository to collectHistorySecrets through a
// mocked RepoClient, which is the only seam the production code exposes.
func runHistory(t *testing.T, dir string, headValues map[string]bool) *checker.SecretHygieneData {
	t.Helper()
	ctrl := gomock.NewController(t)
	client := mockrepo.NewMockRepoClient(ctrl)
	client.EXPECT().LocalPath().Return(dir, nil).AnyTimes()

	results := &checker.SecretHygieneData{}
	req := &checker.CheckRequest{RepoClient: client}
	if headValues == nil {
		headValues = map[string]bool{}
	}
	if err := collectHistorySecrets(req, results, headValues); err != nil {
		t.Fatalf("collectHistorySecrets: %v", err)
	}
	return results
}

// Case 1 -- the behaviour the check exists for, and the one the corpus
// evaluation could not demonstrate: a credential committed and then deleted is
// still retrievable, so it must be reported.
func TestHistoryDetectsRemovedCredential(t *testing.T) {
	t.Parallel()
	dir := newHistoryFixture(t, []commitSpec{
		{files: map[string]string{"config.py": "AWS_ACCESS_KEY_ID = " + fxAWSKeyID + "\n"}},
		{files: map[string]string{"config.py": "AWS_ACCESS_KEY_ID = os.environ['K']\n"}},
	})
	got := runHistory(t, dir, nil)

	if !got.HistoryAvailable {
		t.Fatal("HistoryAvailable false for a repository with history")
	}
	if len(got.Secrets) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got.Secrets), got.Secrets)
	}
	s := got.Secrets[0]
	if !s.InHistory {
		t.Error("finding is not marked InHistory")
	}
	if s.DetectorID != "aws-access-key-id" {
		t.Errorf("DetectorID = %q, want aws-access-key-id", s.DetectorID)
	}
	if s.Location == nil || s.Location.Path != "config.py" {
		t.Errorf("Location = %+v, want config.py", s.Location)
	}
	// The credential lives in the PARENT of the commit that removed it.
	if s.CommitSHA == "" {
		t.Error("CommitSHA empty; a history finding must name the commit that still holds it")
	}
}

// Case 2 -- a credential still present at HEAD is an unremediated exposure,
// already reported by the tree scan. Reporting it here too would double-count
// and blur the distinction the scoring policy depends on.
func TestHistorySuppressesCredentialsStillAtHead(t *testing.T) {
	t.Parallel()
	dir := newHistoryFixture(t, []commitSpec{
		{files: map[string]string{"a.py": "K = " + fxAWSKeyID + "\n"}},
		{files: map[string]string{"a.py": "K = " + fxAWSKeyID + "\nother = 1\n"}},
	})
	got := runHistory(t, dir, map[string]bool{fxAWSKeyID: true})
	if len(got.Secrets) != 0 {
		t.Errorf("got %d findings, want 0 -- HEAD values must be suppressed: %+v",
			len(got.Secrets), got.Secrets)
	}
}

// Case 3 -- the history scan must apply the same vendored/test/documentation
// exclusions as the tree scan. If the two used different filters, a difference
// between their counts would reflect the filters rather than remediation
// behaviour, which is what Section VI compares.
func TestHistoryAppliesTheSameNonProductionExclusions(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"vendor/dep/config.py",
		"testdata/config.py",
		"docs/example.md",
	} {
		dir := newHistoryFixture(t, []commitSpec{
			{files: map[string]string{path: "K = " + fxAWSKeyID + "\n"}},
			{deleted: []string{path}},
		})
		if got := runHistory(t, dir, nil); len(got.Secrets) != 0 {
			t.Errorf("%s: got %d findings, want 0", path, len(got.Secrets))
		}
	}
}

// Case 4 -- a credential touched across several commits is one exposure, not
// one per commit.
func TestHistoryDeduplicatesAcrossCommits(t *testing.T) {
	t.Parallel()
	dir := newHistoryFixture(t, []commitSpec{
		{files: map[string]string{"c.py": "K = " + fxGitHubPAT + "\n"}},
		{files: map[string]string{"c.py": "K = " + fxGitHubPAT + "\nx = 1\n"}},
		{files: map[string]string{"c.py": "K = " + fxGitHubPAT + "\nx = 2\n"}},
		{files: map[string]string{"c.py": "clean = True\n"}},
	})
	got := runHistory(t, dir, nil)
	if len(got.Secrets) != 1 {
		t.Errorf("got %d findings, want 1 after de-duplication: %+v",
			len(got.Secrets), got.Secrets)
	}
}

// Case 5 -- a root commit has no parent to diff. A credential introduced there
// and never removed is still in the tree, so the HEAD scan owns it.
func TestHistorySkipsRootCommit(t *testing.T) {
	t.Parallel()
	dir := newHistoryFixture(t, []commitSpec{
		{files: map[string]string{"only.py": "K = " + fxAWSKeyID + "\n"}},
	})
	got := runHistory(t, dir, nil)
	if !got.HistoryAvailable {
		t.Error("HistoryAvailable should be true even when only a root commit exists")
	}
	if len(got.Secrets) != 0 {
		t.Errorf("got %d findings from a root commit, want 0", len(got.Secrets))
	}
}

// Case 6 -- under Scorecard's default --file-mode archive there is no .git at
// all. That must surface as "not evaluated", never as a clean result.
func TestHistoryUnavailableWithoutGitDirectory(t *testing.T) {
	t.Parallel()
	got := runHistory(t, t.TempDir(), nil)
	if got.HistoryAvailable {
		t.Error("HistoryAvailable true for a directory with no repository")
	}
	if got.CommitsScanned != 0 {
		t.Errorf("CommitsScanned = %d, want 0", got.CommitsScanned)
	}
	if len(got.Secrets) != 0 {
		t.Errorf("got %d findings with no repository, want 0", len(got.Secrets))
	}
}

// Case 7 -- the walk is bounded, and Section VII states that bound as a recall
// limitation. An untested constant is a claim nobody has checked.
func TestHistoryStopsAtTheCommitCap(t *testing.T) {
	t.Parallel()
	commits := make([]commitSpec, 0, maxHistoryCommits+10)
	commits = append(commits, commitSpec{
		files: map[string]string{"f.txt": "start\n"},
	})
	for i := 0; i < maxHistoryCommits+9; i++ {
		commits = append(commits, commitSpec{
			files: map[string]string{"f.txt": "line " + string(rune('a'+i%26)) + "\n"},
		})
	}
	got := runHistory(t, newHistoryFixture(t, commits), nil)
	if got.CommitsScanned != maxHistoryCommits {
		t.Errorf("CommitsScanned = %d, want the cap of %d",
			got.CommitsScanned, maxHistoryCommits)
	}
}

// Case 8 -- the project's standing rule: a detected credential's value must
// never reach a report, a log, or any stored field. ExposedSecret carries no
// value field by design; this fails if one is ever added and populated.
func TestHistoryNeverRecordsTheCredentialValue(t *testing.T) {
	t.Parallel()
	dir := newHistoryFixture(t, []commitSpec{
		{files: map[string]string{"s.py": "K = " + fxStripeLive + "\n"}},
		{deleted: []string{"s.py"}},
	})
	got := runHistory(t, dir, nil)
	if len(got.Secrets) != 1 {
		t.Fatalf("expected the fixture to produce one finding, got %d", len(got.Secrets))
	}
	for _, s := range got.Secrets {
		fields := []string{s.DetectorID, s.CommitSHA}
		if s.Location != nil {
			fields = append(fields, s.Location.Path, s.Location.Snippet)
		}
		for _, f := range fields {
			if strings.Contains(f, fxStripeLive) {
				t.Error("a credential value reached an exported field")
			}
		}
	}
}
