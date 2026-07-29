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

package hasHallucinatedDependency

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
)

func asBoolPointer(b bool) *bool       { return &b }
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
			name: "no manifests found",
			raw: &checker.RawResults{
				HallucinatedDependenciesResults: checker.HallucinatedDependenciesData{},
			},
			outcomes: []finding.Outcome{finding.OutcomeNotApplicable},
		},
		{
			name: "existing and hallucinated dependencies",
			raw: &checker.RawResults{
				HallucinatedDependenciesResults: checker.HallucinatedDependenciesData{
					Dependencies: []checker.HallucinatedDependency{
						{
							Name:      "requests",
							Ecosystem: "pypi",
							Location:  &checker.File{Path: "requirements.txt"},
							Exists:    asBoolPointer(true),
						},
						{
							Name:      "definitely-not-a-real-package-xyz",
							Ecosystem: "pypi",
							Location:  &checker.File{Path: "requirements.txt"},
							Exists:    asBoolPointer(false),
						},
					},
				},
			},
			outcomes: []finding.Outcome{finding.OutcomeFalse, finding.OutcomeTrue},
		},
		{
			name: "lookup error is reported separately from hallucination",
			raw: &checker.RawResults{
				HallucinatedDependenciesResults: checker.HallucinatedDependenciesData{
					Dependencies: []checker.HallucinatedDependency{
						{
							Name:      "flaky-pkg",
							Ecosystem: "npm",
							Location:  &checker.File{Path: "package.json"},
							Error:     asStringPointer("registry timeout"),
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
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
			for i := range tt.outcomes {
				if diff := cmp.Diff(tt.outcomes[i], findings[i].Outcome); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// Test_Run_transientDistinction verifies that a resolved-graph anomaly
// (lockfile entry, Transient: true) and a direct-manifest hallucination
// (Transient: false) are never conflated: both produce OutcomeTrue, but
// with distinguishable messages and a transient value callers can group by.
func Test_Run_transientDistinction(t *testing.T) {
	t.Parallel()

	raw := &checker.RawResults{
		HallucinatedDependenciesResults: checker.HallucinatedDependenciesData{
			Dependencies: []checker.HallucinatedDependency{
				{
					Name:      "definitely-not-a-real-package-xyz",
					Ecosystem: "pypi",
					Location:  &checker.File{Path: "requirements.txt"},
					Exists:    asBoolPointer(false),
					Transient: false,
				},
				{
					Name:      "totally-fake-lockfile-entry-xyz",
					Ecosystem: "npm",
					Location:  &checker.File{Path: "package-lock.json"},
					Exists:    asBoolPointer(false),
					Transient: true,
				},
			},
		},
	}

	findings, _, err := Run(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	direct, transient := findings[0], findings[1]

	if direct.Values[TransientKey] != "false" {
		t.Errorf("direct finding: got transient=%q, want %q", direct.Values[TransientKey], "false")
	}
	if transient.Values[TransientKey] != "true" {
		t.Errorf("lockfile finding: got transient=%q, want %q", transient.Values[TransientKey], "true")
	}

	if strings.Contains(direct.Message, "resolved-graph") {
		t.Errorf("direct finding message should not use resolved-graph framing: %q", direct.Message)
	}
	if !strings.Contains(direct.Message, "AI-hallucinated") {
		t.Errorf("direct finding message should reference AI-hallucination: %q", direct.Message)
	}

	if !strings.Contains(transient.Message, "resolved-graph") {
		t.Errorf("lockfile finding message should use resolved-graph framing: %q", transient.Message)
	}
	if strings.Contains(transient.Message, "AI-hallucinated package name") {
		t.Errorf("lockfile finding message should not claim AI-hallucination: %q", transient.Message)
	}

	if direct.Message == transient.Message {
		t.Errorf("direct and transient findings must not share the same message")
	}
}
