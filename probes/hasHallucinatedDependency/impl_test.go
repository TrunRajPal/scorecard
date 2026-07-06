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
