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
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Environment variables controlling the on-disk registry existence cache.
// This check is the only Scorecard check that hammers a public package
// registry once per manifest dependency; at dataset-evaluation scale (many
// repos, many overlapping/recurring package names -- Spracklen et al. found
// 43% of hallucinated names recur across prompts) an in-memory-only cache
// (see resolveExistence) isn't enough, since it's discarded at the end of
// every process run.
const (
	// hallucinatedDepsCachePathEnv overrides the cache file location.
	hallucinatedDepsCachePathEnv = "SCORECARD_HALLUCINATED_DEPS_CACHE_PATH"
	// hallucinatedDepsCacheDisableEnv, if set to any non-empty value, turns
	// off the disk cache entirely.
	hallucinatedDepsCacheDisableEnv = "SCORECARD_HALLUCINATED_DEPS_NO_CACHE"
	// hallucinatedDepsCacheTTLEnv overrides how long a cached result is
	// trusted before being re-checked, as a Go duration string (e.g. "72h").
	hallucinatedDepsCacheTTLEnv = "SCORECARD_HALLUCINATED_DEPS_CACHE_TTL"

	defaultCacheTTL = 24 * time.Hour
)

type registryCacheEntry struct {
	CheckedAt time.Time `json:"checkedAt"`
	Exists    bool      `json:"exists"`
}

// registryCache is a best-effort, process-spanning cache of registry
// existence lookups keyed by "ecosystem:name". Caching is a performance
// optimization only: any failure to load, parse, or save the cache file is
// swallowed so it can never cause the check itself to fail or behave
// differently -- a nil *registryCache degrades transparently to "no cache".
type registryCache struct {
	path    string
	ttl     time.Duration
	entries map[string]registryCacheEntry
}

// loadRegistryCache reads the on-disk cache, or returns nil if disabled or
// unavailable (e.g. no user cache dir on this platform).
func loadRegistryCache() *registryCache {
	if os.Getenv(hallucinatedDepsCacheDisableEnv) != "" {
		return nil
	}

	path := os.Getenv(hallucinatedDepsCachePathEnv)
	if path == "" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return nil
		}
		path = filepath.Join(dir, "scorecard", "hallucinated-dependencies-registry-cache.json")
	}

	ttl := defaultCacheTTL
	if s := os.Getenv(hallucinatedDepsCacheTTLEnv); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			ttl = d
		}
	}

	c := &registryCache{path: path, ttl: ttl, entries: map[string]registryCacheEntry{}}

	data, err := os.ReadFile(path)
	if err != nil {
		return c // no cache file yet -- start empty, not an error
	}
	// A corrupt cache file starts fresh rather than failing the check.
	_ = json.Unmarshal(data, &c.entries)

	return c
}

func (c *registryCache) get(key string) (exists, ok bool) {
	if c == nil {
		return false, false
	}
	e, found := c.entries[key]
	if !found || time.Since(e.CheckedAt) > c.ttl {
		return false, false
	}
	return e.Exists, true
}

func (c *registryCache) set(key string, exists bool) {
	if c == nil {
		return
	}
	c.entries[key] = registryCacheEntry{Exists: exists, CheckedAt: time.Now()}
}

// save persists the cache atomically (write-then-rename). Concurrent
// scorecard processes racing on the same cache file may clobber each
// other's writes; for the sequential, single-repo-at-a-time evaluation runs
// this is built for, that's an acceptable tradeoff against the complexity
// of file locking.
func (c *registryCache) save() {
	if c == nil {
		return
	}
	data, err := json.Marshal(c.entries)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, c.path)
}

// cachingExistenceChecker wraps an existenceChecker with the disk cache.
// Lookup errors are never cached -- see the package-level note on
// resolveExistence about not conflating registry errors with hallucination.
func cachingExistenceChecker(cache *registryCache, check existenceChecker) existenceChecker {
	return func(ecosystem, name string) (bool, error) {
		key := ecosystem + ":" + name
		if exists, ok := cache.get(key); ok {
			return exists, nil
		}
		exists, err := check(ecosystem, name)
		if err == nil {
			cache.set(key, exists)
		}
		return exists, err
	}
}
