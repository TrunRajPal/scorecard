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

// EXPERIMENTAL ALTERNATIVE DEPENDENCY EXTRACTOR
//
// This file provides a second implementation of the manifest and lockfile
// parsing that feeds the Hallucinated-Dependencies check, built on
// osv-scalibr rather than on the hand-written parsers in
// hallucinated_dependencies.go and hallucinated_dependencies_lockfile.go.
//
// It is OFF by default and selected with:
//
//	SCORECARD_HALLUCINATED_DEPS_EXTRACTOR=scalibr
//
// WHY A SECOND IMPLEMENTATION RATHER THAN A REPLACEMENT. The hand-written
// parsers have been validated against four corpora and had two rounds of
// false-positive fixes applied to them. Replacing them outright would
// discard that validation on the assumption that the new path behaves
// identically. Running both allows the difference to be measured across the
// same corpora and reported, which is the same standard of evidence applied
// to every other decision in this project.
//
// WHAT SCALIBR BUYS. Extractors for lockfile formats the hand-written
// parsers do not cover -- yarn.lock, pnpm-lock.yaml, uv.lock,
// pdm.lock -- maintained by a third party and already an indirect
// dependency of upstream Scorecard via osv-scanner. No new module is added
// to go.mod by this file.
//
// WHAT SCALIBR DOES NOT DO. It reports workspace packages -- packages the
// repository defines itself -- as ordinary dependencies. Those never reach
// a registry, so checking them for existence reports a hallucination for a
// package sitting in the same repository. That exact false positive was
// found on tambo-ai/tambo during the AIDev evaluation. The local-package
// exclusion is therefore re-applied here on top of scalibr's output, and
// duplicate entries are collapsed.

package raw

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	scalibrextractor "github.com/google/osv-scalibr/extractor"
	scalibrfilesystem "github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
)

const (
	// extractorEnv selects the dependency extractor implementation.
	extractorEnv = "SCORECARD_HALLUCINATED_DEPS_EXTRACTOR"
	// extractorScalibr is the value that enables this path.
	extractorScalibr = "scalibr"
)

// useScalibrExtractor reports whether the experimental extractor is selected.
func useScalibrExtractor() bool {
	return strings.EqualFold(os.Getenv(extractorEnv), extractorScalibr)
}

// scalibrExtractor pairs an extractor with the classification this check
// needs, which scalibr itself does not carry: whether a file describes the
// dependencies a developer declared (direct) or the resolved graph a package
// manager produced (transient).
type scalibrExtractor struct {
	impl      scalibrfilesystem.Extractor
	ecosystem string
	transient bool
}

// scalibrExtractors is the set applied to a repository.
//
// requirements reads a direct manifest; the remainder read lockfiles and are
// marked transient, matching the direct-vs-resolved split the probe and
// scoring layers already understand.
//
// NOTE: scalibr's packagejson extractor is deliberately NOT used, and this
// is the single most important thing to understand about this file.
//
// That extractor answers "which package is this?" -- for a package.json
// declaring name "root", it returns one package, "root". It does not return
// the contents of "dependencies". It exists to identify installed packages
// inside node_modules, not to read a manifest's dependency list.
//
// Substituting it for the hand-written package.json parser would therefore
// have silently removed direct npm dependency detection: the very signal
// that produces this check's headline result. It was caught by running both
// implementations over the same fixture and diffing, which is the reason
// this path was built alongside the original rather than replacing it.
//
// collectPackageJSON from the hand-written path is called directly instead.
//
// NOTE: scalibr's requirements extractor is excluded for the same class of
// reason, found the same way.
//
// It silently drops every PyPI name containing a dot. Given a requirements
// file listing zope.interface, ruamel.yaml, backports.zoneinfo and
// Mastodon.py, it returns none of them -- no error, no warning, they are
// simply absent. Dots are legal in PyPI names, and these are not obscure
// packages: zope.interface sits under a large part of the Python ecosystem.
//
// The corpus comparison surfaced it as three "missing" dependencies in
// home-assistant/core (jaraco.abode, Mastodon.py, pushbullet.py). The
// hand-written requirements parser handles them correctly, so it is kept.
//
// The lockfile extractors do NOT share this bug -- poetrylock and
// pipfilelock both return zope.interface intact -- which is why they are
// still used. This is the boundary the comparison established: scalibr for
// lockfile formats, hand-written parsers for direct manifests.
func scalibrExtractors() []scalibrExtractor {
	return []scalibrExtractor{
		{packagelockjson.New(packagelockjson.DefaultConfig()), ecosystemNpm, true},
		{yarnlock.Extractor{}, ecosystemNpm, true},
		{pnpmlock.Extractor{}, ecosystemNpm, true},
		{poetrylock.Extractor{}, ecosystemPyPI, true},
		{pipfilelock.Extractor{}, ecosystemPyPI, true},
		{uvlock.Extractor{}, ecosystemPyPI, true},
		{pdmlock.Extractor{}, ecosystemPyPI, true},
	}
}

// collectViaScalibr gathers dependencies using scalibr's extractors.
func collectViaScalibr(c *checker.CheckRequest) (checker.HallucinatedDependenciesData, error) {
	var results checker.HallucinatedDependenciesData

	// Same first step as the hand-written path: a package this repository
	// defines itself is resolved locally and must never be checked against a
	// registry. Scalibr does not do this, so it is applied to its output.
	local, err := collectLocalPackageNames(c)
	if err != nil {
		return results, err
	}

	paths, err := c.RepoClient.ListFiles(func(string) (bool, error) { return true, nil })
	if err != nil {
		return results, fmt.Errorf("RepoClient.ListFiles: %w", err)
	}

	// Direct manifests are read by the hand-written parsers. See the note on
	// scalibrExtractors: scalibr's packagejson extractor returns the package's
	// own identity rather than its dependencies, and its requirements
	// extractor drops dotted PyPI names.
	if err := collectPythonRequirements(c, &results); err != nil {
		return results, err
	}
	if err := collectPackageJSON(c, &results, local); err != nil {
		return results, err
	}

	// Dependencies the manifest installs from a URL, git remote, local path
	// or workspace are not registry-resolvable. Scalibr's Package struct
	// carries nothing that distinguishes them, so package.json is used as the
	// authority. See collectNonRegistryNames.
	nonRegistry, err := collectNonRegistryNames(c)
	if err != nil {
		return results, err
	}

	vfs := newRepoFS(c, paths)
	ctx := context.Background()

	// seen collapses duplicates. Scalibr can report the same package more
	// than once from a single lockfile -- a workspace package appears both as
	// its own entry and as the symlink that points at it -- and the same name
	// legitimately appears across several manifests in a monorepo.
	seen := map[string]bool{}
	for _, d := range results.Dependencies {
		seen[d.Ecosystem+":"+d.Name] = true
	}

	for _, ex := range scalibrExtractors() {
		for _, p := range paths {
			if !ex.impl.FileRequired(repoFileAPI{path: p, fsys: vfs}) {
				continue
			}

			pkgs, err := extractOne(ctx, ex.impl, vfs, p)
			if err != nil {
				// A file that cannot be parsed is not evidence of anything.
				// The hand-written path takes the same view of malformed
				// input: skip it rather than report a finding.
				continue
			}

			for _, pkg := range pkgs {
				name := strings.TrimSpace(pkg.Name)
				if name == "" {
					continue
				}
				// PEP 503 normalisation is applied to the STORED name, not
				// only to the lookup key, so that both extractor paths report
				// the same spelling and share cache entries. Without this the
				// scalibr path writes "Django" where the hand-written path
				// writes "django", doubling registry lookups.
				if ex.ecosystem == ecosystemPyPI {
					name = normalizePyPIName(name)
				}
				if local[name] || nonRegistry[name] {
					// Workspace / self-defined package, or one installed from
					// somewhere other than the registry.
					continue
				}
				key := ex.ecosystem + ":" + name
				if seen[key] {
					continue
				}
				seen[key] = true

				results.Dependencies = append(results.Dependencies, checker.HallucinatedDependency{
					Name:      name,
					Ecosystem: ex.ecosystem,
					Transient: ex.transient,
					Location: &checker.File{
						Path:   p,
						Type:   finding.FileTypeSource,
						Offset: 1, EndOffset: 1,
					},
				})
			}
		}
	}

	// Deterministic order, so two runs over the same repository produce
	// byte-identical output.
	sort.Slice(results.Dependencies, func(i, j int) bool {
		a, b := results.Dependencies[i], results.Dependencies[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		return a.Name < b.Name
	})

	cache := loadRegistryCache()
	resolveExistence(&results, cachingExistenceChecker(cache, checkRegistryExistence))
	cache.save()

	return results, nil
}

// extractOne runs a single extractor against a single file.
func extractOne(ctx context.Context, ex scalibrfilesystem.Extractor,
	vfs *repoFS, p string,
) ([]*scalibrextractor.Package, error) {
	rc, err := vfs.repoClient.GetFileReader(p)
	if err != nil {
		return nil, fmt.Errorf("GetFileReader %q: %w", p, err)
	}
	defer rc.Close()

	info, err := vfs.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", p, err)
	}

	inv, err := ex.Extract(ctx, &scalibrfilesystem.ScanInput{
		FS:     vfs,
		Path:   p,
		Root:   ".",
		Info:   info,
		Reader: rc,
	})
	if err != nil {
		return nil, fmt.Errorf("extract %q: %w", p, err)
	}
	return inv.Packages, nil
}

// ---------------------------------------------------------------------------
// Filesystem shim
//
// Scalibr extractors expect an fs.FS: packagelockjson, for example, checks
// for a sibling npm-shrinkwrap.json before parsing. Scorecard exposes a
// RepoClient instead, which lists paths and opens readers but has no
// directory or stat semantics. This adapter supplies the missing pieces from
// the file list, so no extractor is given a real filesystem it could walk
// outside the repository.
// ---------------------------------------------------------------------------

type repoFS struct {
	repoClient interface {
		GetFileReader(string) (io.ReadCloser, error)
	}
	// files is the set of paths known to exist, so Open and Stat can fail
	// fast for anything the repository does not contain.
	files map[string]bool
	dirs  map[string]bool
}

func newRepoFS(c *checker.CheckRequest, paths []string) *repoFS {
	r := &repoFS{
		repoClient: c.RepoClient,
		files:      make(map[string]bool, len(paths)),
		dirs:       map[string]bool{".": true},
	}
	for _, p := range paths {
		r.files[p] = true
		for d := path.Dir(p); d != "." && d != "/" && d != ""; d = path.Dir(d) {
			r.dirs[d] = true
		}
	}
	return r
}

func (r *repoFS) Open(name string) (fs.File, error) {
	if !r.files[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	rc, err := r.repoClient.GetFileReader(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &repoFile{ReadCloser: rc, name: name}, nil
}

func (r *repoFS) Stat(name string) (fs.FileInfo, error) {
	if r.files[name] {
		return repoFileInfo{name: path.Base(name)}, nil
	}
	if r.dirs[name] {
		return repoFileInfo{name: path.Base(name), dir: true}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}

func (r *repoFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !r.dirs[name] {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	seen := map[string]bool{}
	var out []fs.DirEntry
	for f := range r.files {
		d := path.Dir(f)
		if d != name {
			continue
		}
		base := path.Base(f)
		if seen[base] {
			continue
		}
		seen[base] = true
		out = append(out, fs.FileInfoToDirEntry(repoFileInfo{name: base}))
	}
	for d := range r.dirs {
		if path.Dir(d) != name || d == name {
			continue
		}
		base := path.Base(d)
		if seen[base] {
			continue
		}
		seen[base] = true
		out = append(out, fs.FileInfoToDirEntry(repoFileInfo{name: base, dir: true}))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// repoFileAPI adapts a path for the FileRequired predicate.
type repoFileAPI struct {
	path string
	fsys *repoFS
}

func (a repoFileAPI) Path() string               { return a.path }
func (a repoFileAPI) Stat() (fs.FileInfo, error) { return a.fsys.Stat(a.path) }

type repoFile struct {
	io.ReadCloser
	name string
}

func (f *repoFile) Stat() (fs.FileInfo, error) { return repoFileInfo{name: path.Base(f.name)}, nil }

type repoFileInfo struct {
	name string
	dir  bool
}

func (i repoFileInfo) Name() string { return i.name }
func (i repoFileInfo) Size() int64  { return 0 }
func (i repoFileInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (i repoFileInfo) ModTime() time.Time { return time.Time{} }
func (i repoFileInfo) IsDir() bool        { return i.dir }
func (i repoFileInfo) Sys() any           { return nil }
