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
	"context"
	"io"
	"os"
	"strings"
	"testing"

	scalibrfilesystem "github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
)

// fakeReaderClient is the minimum RepoClient surface repoFS needs.
type fakeReaderClient struct{ files map[string]string }

func (f fakeReaderClient) GetFileReader(p string) (io.ReadCloser, error) {
	c, ok := f.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(strings.NewReader(c)), nil
}

func newTestRepoFS(files map[string]string) *repoFS {
	r := &repoFS{
		repoClient: fakeReaderClient{files: files},
		files:      map[string]bool{},
		dirs:       map[string]bool{".": true},
	}
	for p := range files {
		r.files[p] = true
		for d := dirOf(p); d != "." && d != ""; d = dirOf(d) {
			r.dirs[d] = true
		}
	}
	return r
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "."
	}
	return p[:i]
}

func TestUseScalibrExtractorFlag(t *testing.T) {
	t.Setenv(extractorEnv, "")
	if useScalibrExtractor() {
		t.Error("extractor must default to the hand-written parsers when unset")
	}
	t.Setenv(extractorEnv, "scalibr")
	if !useScalibrExtractor() {
		t.Error("SCORECARD_HALLUCINATED_DEPS_EXTRACTOR=scalibr should select scalibr")
	}
	t.Setenv(extractorEnv, "SCALIBR")
	if !useScalibrExtractor() {
		t.Error("flag comparison should be case-insensitive")
	}
	t.Setenv(extractorEnv, "something-else")
	if useScalibrExtractor() {
		t.Error("an unrecognised value must fall back to the default path")
	}
}

// TestRepoFSSatisfiesScalibr checks the shim that lets scalibr extractors run
// against Scorecard's RepoClient. packagelockjson calls FS.Open to look for a
// sibling npm-shrinkwrap.json before parsing, so a nil FS panics.
func TestRepoFSSatisfiesScalibr(t *testing.T) {
	t.Parallel()
	vfs := newTestRepoFS(map[string]string{
		"package-lock.json":         `{}`,
		"packages/app/package.json": `{"name":"app"}`,
	})

	if _, err := vfs.Open("package-lock.json"); err != nil {
		t.Errorf("Open on an existing file: %v", err)
	}
	if _, err := vfs.Open("does-not-exist.json"); err == nil {
		t.Error("Open on a missing file should fail, so extractors can probe safely")
	}
	if _, err := vfs.Stat("packages"); err != nil {
		t.Errorf("Stat on a synthesised directory: %v", err)
	}
	fi, err := vfs.Stat("packages/app")
	if err != nil || !fi.IsDir() {
		t.Errorf("nested directory should stat as a directory, got %v %v", fi, err)
	}
	entries, err := vfs.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 2 {
		t.Errorf("ReadDir(.) = %v, want package-lock.json and packages", names)
	}
}

// TestScalibrPackageJSONExtractorDoesNotYieldDependencies documents, and
// guards, the reason scalibr's packagejson extractor is excluded from
// scalibrExtractors.
//
// It answers "which package is this?", not "what does it depend on". Adding
// it to the extractor list would silently remove direct npm dependency
// detection -- the signal behind this check's headline result. This test
// fails if a future scalibr version changes that behaviour, at which point
// the exclusion should be revisited deliberately rather than by accident.
func TestScalibrPackageJSONExtractorDoesNotYieldDependencies(t *testing.T) {
	t.Parallel()
	content := `{"name":"root","version":"1.0.0",
		"dependencies":{"express":"4.18.2","totally-fake-pkg":"1.0.0"}}`
	vfs := newTestRepoFS(map[string]string{"package.json": content})

	e := packagejson.New(packagejson.DefaultConfig())
	inv, err := e.Extract(context.Background(), &scalibrfilesystem.ScanInput{
		Path: "package.json", Root: ".", FS: vfs,
		Reader: strings.NewReader(content),
	})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	for _, p := range inv.Packages {
		if p.Name == "express" || p.Name == "totally-fake-pkg" {
			t.Fatalf("scalibr's packagejson extractor now returns declared "+
				"dependencies (%q). The exclusion in scalibrExtractors was "+
				"based on it NOT doing so -- revisit it deliberately.", p.Name)
		}
	}
	if len(inv.Packages) != 1 || inv.Packages[0].Name != "root" {
		t.Errorf("expected only the package's own identity, got %+v", inv.Packages)
	}
}

// TestScalibrExtractorsCoverNewLockfileFormats guards the reason this path
// exists: formats the hand-written parsers cannot read.
func TestScalibrExtractorsCoverNewLockfileFormats(t *testing.T) {
	t.Parallel()
	exts := scalibrExtractors()
	if len(exts) == 0 {
		t.Fatal("no extractors registered")
	}
	want := map[string]bool{
		"yarn.lock": false, "pnpm-lock.yaml": false, "uv.lock": false,
	}
	vfs := newTestRepoFS(map[string]string{
		"yarn.lock": "", "pnpm-lock.yaml": "", "uv.lock": "",
	})
	for _, ex := range exts {
		for f := range want {
			if ex.impl.FileRequired(repoFileAPI{path: f, fsys: vfs}) {
				want[f] = true
			}
		}
	}
	for f, covered := range want {
		if !covered {
			t.Errorf("no registered extractor claims %q", f)
		}
	}
}

// TestScalibrLockfilesMarkedTransient keeps the direct-vs-resolved split the
// probe and scoring layers rely on.
func TestScalibrLockfilesMarkedTransient(t *testing.T) {
	t.Parallel()
	for _, ex := range scalibrExtractors() {
		name := ex.impl.Name()
		isRequirements := strings.Contains(name, "requirements")
		if isRequirements && ex.transient {
			t.Errorf("%s reads a direct manifest and must not be transient", name)
		}
		if !isRequirements && !ex.transient {
			t.Errorf("%s reads a lockfile and must be marked transient", name)
		}
		if ex.ecosystem != ecosystemPyPI && ex.ecosystem != ecosystemNpm {
			t.Errorf("%s has unexpected ecosystem %q", name, ex.ecosystem)
		}
	}
}
