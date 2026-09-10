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

package hasExposedSecret

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
)

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
			name: "clean repository with history inspected",
			raw: &checker.RawResults{
				SecretHygieneResults: checker.SecretHygieneData{
					HistoryAvailable: true,
					CommitsScanned:   42,
				},
			},
			outcomes: []finding.Outcome{finding.OutcomeFalse},
		},
		{
			name: "clean tree but history not available yields both false and not-available",
			raw: &checker.RawResults{
				SecretHygieneResults: checker.SecretHygieneData{
					HistoryAvailable: false,
				},
			},
			// The not-available finding must be present so a partial
			// evaluation is not mistaken for a clean one.
			outcomes: []finding.Outcome{finding.OutcomeNotAvailable, finding.OutcomeFalse},
		},
		{
			name: "credential in the current tree",
			raw: &checker.RawResults{
				SecretHygieneResults: checker.SecretHygieneData{
					HistoryAvailable: true,
					Secrets: []checker.ExposedSecret{
						{
							DetectorID: "aws-access-key-id",
							Location:   &checker.File{Path: "config.py", Offset: 2},
							InHistory:  false,
						},
					},
				},
			},
			outcomes: []finding.Outcome{finding.OutcomeTrue},
		},
		{
			name: "credential only in history",
			raw: &checker.RawResults{
				SecretHygieneResults: checker.SecretHygieneData{
					HistoryAvailable: true,
					Secrets: []checker.ExposedSecret{
						{
							DetectorID: "aws-access-key-id",
							Location:   &checker.File{Path: "config.py", Offset: 2},
							InHistory:  true,
							CommitSHA:  "acc35350f7c1b0a2e4d6f8901234567890abcdef",
						},
					},
				},
			},
			outcomes: []finding.Outcome{finding.OutcomeTrue},
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

// Test_Run_scopeDistinction is the central guarantee of this probe: a
// current-tree exposure and an incompletely-remediated history remnant are
// different failure modes and must stay distinguishable downstream.
func Test_Run_scopeDistinction(t *testing.T) {
	t.Parallel()

	raw := &checker.RawResults{
		SecretHygieneResults: checker.SecretHygieneData{
			HistoryAvailable: true,
			Secrets: []checker.ExposedSecret{
				{
					DetectorID: "github-personal-access-token",
					Location:   &checker.File{Path: "settings.py", Offset: 1},
					InHistory:  false,
				},
				{
					DetectorID: "aws-access-key-id",
					Location:   &checker.File{Path: "config.py", Offset: 2},
					InHistory:  true,
					CommitSHA:  "acc35350f7c1b0a2e4d6f8901234567890abcdef",
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

	head, history := findings[0], findings[1]

	if head.Values[ScopeKey] != ScopeHead {
		t.Errorf("current-tree finding: got scope %q, want %q", head.Values[ScopeKey], ScopeHead)
	}
	if history.Values[ScopeKey] != ScopeHistory {
		t.Errorf("history finding: got scope %q, want %q", history.Values[ScopeKey], ScopeHistory)
	}
	if head.Values[DetectorKey] != "github-personal-access-token" {
		t.Errorf("unexpected detector on current-tree finding: %q", head.Values[DetectorKey])
	}

	// The history message must not describe a current-tree exposure, and
	// must point at the commit that still holds the credential.
	if !strings.Contains(history.Message, "still retrievable from git history") {
		t.Errorf("history message should describe an incomplete remediation: %q", history.Message)
	}
	if !strings.Contains(history.Message, "acc3535") {
		t.Errorf("history message should name the short commit SHA: %q", history.Message)
	}
	if strings.Contains(head.Message, "git history") {
		t.Errorf("current-tree message should not mention history: %q", head.Message)
	}
}

// Test_Run_neverLeaksCredentialValues enforces the handling policy: no
// finding may carry the credential itself. The raw layer never populates
// Snippet for this check, and nothing here may reintroduce it.
func Test_Run_neverLeaksCredentialValues(t *testing.T) {
	t.Parallel()

	// Synthetic and shape-only. Assembled from fragments so no complete
	// credential pattern appears as a literal in this file -- GitHub's push
	// protection blocks pushes containing such literals, having classified
	// these fixtures as live credentials.
	synthetic := "AKIA" + "7TQ2VBRJ4KDNMZLH"
	raw := &checker.RawResults{
		SecretHygieneResults: checker.SecretHygieneData{
			HistoryAvailable: true,
			Secrets: []checker.ExposedSecret{
				{
					DetectorID: "aws-access-key-id",
					// A hostile/buggy raw layer putting the value in Snippet
					// must still not result in it reaching a finding message.
					Location:  &checker.File{Path: "config.py", Offset: 2, Snippet: synthetic},
					InHistory: false,
				},
			},
		},
	}

	findings, _, err := Run(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := range findings {
		if strings.Contains(findings[i].Message, synthetic) {
			t.Errorf("finding message must never contain the credential value: %q", findings[i].Message)
		}
		for k, v := range findings[i].Values {
			if strings.Contains(v, synthetic) {
				t.Errorf("finding value %q must never contain the credential value: %q", k, v)
			}
		}
	}
}

func TestShortSHA(t *testing.T) {
	t.Parallel()
	if got := shortSHA("acc35350f7c1b0a2e4d6f8901234567890abcdef"); got != "acc3535" {
		t.Errorf("got %q, want %q", got, "acc3535")
	}
	if got := shortSHA("abc"); got != "abc" {
		t.Errorf("short input should pass through, got %q", got)
	}
}
