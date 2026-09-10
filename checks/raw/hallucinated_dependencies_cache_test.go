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

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistryCachePersistsAcrossLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	t.Setenv(hallucinatedDepsCachePathEnv, path)

	calls := 0
	underlying := func(ecosystem, name string) (bool, error) {
		calls++
		return name == "exists-pkg", nil
	}

	cache := loadRegistryCache()
	if cache == nil {
		t.Fatal("expected a non-nil cache")
	}
	checker := cachingExistenceChecker(cache, underlying)

	exists, err := checker(ecosystemPyPI, "exists-pkg")
	if err != nil || !exists {
		t.Fatalf("got (%v, %v), want (true, nil)", exists, err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call to underlying checker, got %d", calls)
	}
	cache.save()

	// A fresh load from the same path should serve the cached result
	// without calling the underlying checker again.
	reloaded := loadRegistryCache()
	reloadedChecker := cachingExistenceChecker(reloaded, underlying)
	exists, err = reloadedChecker(ecosystemPyPI, "exists-pkg")
	if err != nil || !exists {
		t.Fatalf("got (%v, %v), want (true, nil)", exists, err)
	}
	if calls != 1 {
		t.Fatalf("expected cached result to avoid a second call, but calls=%d", calls)
	}
}

func TestRegistryCacheExpiresAfterTTL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	t.Setenv(hallucinatedDepsCachePathEnv, path)
	t.Setenv(hallucinatedDepsCacheTTLEnv, "1ms")

	calls := 0
	underlying := func(ecosystem, name string) (bool, error) {
		calls++
		return false, nil
	}

	cache := loadRegistryCache()
	checker := cachingExistenceChecker(cache, underlying)
	if _, err := checker(ecosystemNpm, "flaky"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	if _, err := checker(ecosystemNpm, "flaky"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected the expired entry to trigger a second call, got %d calls", calls)
	}
}

func TestRegistryCacheDoesNotCacheLookupErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	t.Setenv(hallucinatedDepsCachePathEnv, path)

	calls := 0
	errLookup := errors.New("registry unreachable")
	underlying := func(ecosystem, name string) (bool, error) {
		calls++
		return false, errLookup
	}

	cache := loadRegistryCache()
	checker := cachingExistenceChecker(cache, underlying)

	for i := 0; i < 2; i++ {
		if _, err := checker(ecosystemPyPI, "flaky-pkg"); !errors.Is(err, errLookup) {
			t.Fatalf("expected errLookup, got %v", err)
		}
	}
	if calls != 2 {
		t.Fatalf("expected every call to retry after a lookup error, got %d calls", calls)
	}
}

func TestRegistryCacheDisabled(t *testing.T) {
	t.Setenv(hallucinatedDepsCacheDisableEnv, "1")

	cache := loadRegistryCache()
	if cache != nil {
		t.Fatalf("expected nil cache when disabled, got %+v", cache)
	}

	// A nil cache must degrade transparently rather than panicking.
	checker := cachingExistenceChecker(cache, func(string, string) (bool, error) { return true, nil })
	if exists, err := checker(ecosystemPyPI, "anything"); err != nil || !exists {
		t.Fatalf("got (%v, %v), want (true, nil)", exists, err)
	}
	cache.save()
}
