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

package hasStaleDependency

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
)

func asStringPointer(s string) *string { return &s }

func Test_Run(t *testing.T) {
	t.Parallel()
	//nolint:govet
	tests := []struct {
		name     string
		raw      *checker.RawResults
		outcomes []finding.Outcome
		wantErr  bool
	}{
		{
			// Having nothing to measure is deliberately not a pass: a
			// project using only ranges should not be credited as though
			// its pins had been assessed.
			name: "no exact pins is not applicable, not a pass",
			raw: &checker.RawResults{
				StaleDependenciesResults: checker.StaleDependenciesData{},
			},
			outcomes: []finding.Outcome{finding.OutcomeNotApplicable},
		},
		{
			name: "pin newer than the threshold is current",
			raw: &checker.RawResults{
				StaleDependenciesResults: checker.StaleDependenciesData{
					Dependencies: []checker.StaleDependency{
						{
							Name: "pkg", Ecosystem: "pypi",
							PinnedVersion: "1.9.0", LatestVersion: "2.0.0",
							DaysBehind: 30, VersionsBehind: 1,
							Location: &checker.File{Path: "requirements.txt"},
						},
					},
				},
			},
			outcomes: []finding.Outcome{finding.OutcomeFalse},
		},
		{
			name: "pin at exactly the threshold is stale",
			raw: &checker.RawResults{
				StaleDependenciesResults: checker.StaleDependenciesData{
					Dependencies: []checker.StaleDependency{
						{
							Name: "pkg", Ecosystem: "pypi",
							PinnedVersion: "1.0.0", LatestVersion: "2.0.0",
							DaysBehind: StaleThresholdDays, VersionsBehind: 5,
							Location: &checker.File{Path: "requirements.txt"},
						},
					},
				},
			},
			outcomes: []finding.Outcome{finding.OutcomeTrue},
		},
		{
			name: "undetermined staleness is an error, not a finding",
			raw: &checker.RawResults{
				StaleDependenciesResults: checker.StaleDependenciesData{
					Dependencies: []checker.StaleDependency{
						{
							Name: "pkg", Ecosystem: "npm",
							PinnedVersion: "9.9.9",
							Error:         asStringPointer("pinned version not found on the registry"),
							Location:      &checker.File{Path: "package.json"},
						},
					},
				},
			},
			outcomes: []finding.Outcome{finding.OutcomeError},
		},
		{
			name:    "nil raw results",
			raw:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, s, err := Run(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(Probe, s); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(len(tt.outcomes), len(findings)); diff != "" {
				t.Errorf("finding count mismatch (-want +got):\n%s", diff)
			}
			for i := range tt.outcomes {
				if i >= len(findings) {
					break
				}
				if diff := cmp.Diff(tt.outcomes[i], findings[i].Outcome); diff != "" {
					t.Errorf("outcome %d mismatch (-want +got):\n%s", i, diff)
				}
			}
		})
	}
}

// Test_Run_findingCarriesMeasurements checks that a stale finding reports
// the numbers a maintainer needs to act, rather than only a verdict.
func Test_Run_findingCarriesMeasurements(t *testing.T) {
	t.Parallel()

	raw := &checker.RawResults{
		StaleDependenciesResults: checker.StaleDependenciesData{
			Dependencies: []checker.StaleDependency{
				{
					Name: "requests", Ecosystem: "pypi",
					PinnedVersion: "2.25.0", LatestVersion: "2.34.2",
					DaysBehind: 2009, VersionsBehind: 22,
					Location: &checker.File{Path: "requirements.txt", Offset: 2},
				},
			},
		},
	}

	findings, _, err := Run(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]

	for key, want := range map[string]string{
		NameKey: "requests", EcosystemKey: "pypi",
		PinnedVersionKey: "2.25.0", LatestVersionKey: "2.34.2",
		DaysBehindKey: "2009", VersionsBehindKey: "22",
	} {
		if f.Values[key] != want {
			t.Errorf("value %q: got %q, want %q", key, f.Values[key], want)
		}
	}

	// The message should name both versions and both magnitudes, since a
	// bare "is stale" gives a maintainer nothing to judge urgency by.
	for _, want := range []string{"2.25.0", "2.34.2", "2009", "22"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("message should mention %q: %q", want, f.Message)
		}
	}
}
