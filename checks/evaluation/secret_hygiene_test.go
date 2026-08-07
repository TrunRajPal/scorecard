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

package evaluation

import (
	"strings"
	"testing"

	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/hasExposedSecret"
	scut "github.com/ossf/scorecard/v5/utests"
)

func headSecretFinding() finding.Finding {
	return finding.Finding{
		Probe:   hasExposedSecret.Probe,
		Outcome: finding.OutcomeTrue,
		Values:  map[string]string{hasExposedSecret.ScopeKey: hasExposedSecret.ScopeHead},
	}
}

func historySecretFinding() finding.Finding {
	return finding.Finding{
		Probe:   hasExposedSecret.Probe,
		Outcome: finding.OutcomeTrue,
		Values:  map[string]string{hasExposedSecret.ScopeKey: hasExposedSecret.ScopeHistory},
	}
}

func TestSecretHygiene(t *testing.T) {
	t.Parallel()
	//nolint:govet
	tests := []struct {
		name     string
		findings []finding.Finding
		result   scut.TestReturn
	}{
		{
			name: "no credentials detected",
			findings: []finding.Finding{
				{Probe: hasExposedSecret.Probe, Outcome: finding.OutcomeFalse},
			},
			result: scut.TestReturn{Score: 10},
		},
		{
			// A live credential in version control is an active exposure,
			// not a gradable quality attribute -- one is sufficient for
			// compromise, so the score goes straight to the minimum.
			name:     "a single current-tree credential scores zero",
			findings: []finding.Finding{headSecretFinding()},
			result: scut.TestReturn{
				Score:        0,
				NumberOfWarn: 1,
			},
		},
		{
			name: "many current-tree credentials still score zero, not negative",
			findings: []finding.Finding{
				headSecretFinding(), headSecretFinding(), headSecretFinding(),
			},
			result: scut.TestReturn{
				Score:        0,
				NumberOfWarn: 3,
			},
		},
		{
			// History-only findings deduct proportionally: rotation is the
			// real remediation and is invisible from inside the repository,
			// so this signal carries uncertainty a current-tree finding
			// does not.
			name:     "one history-only credential deducts one point",
			findings: []finding.Finding{historySecretFinding()},
			result: scut.TestReturn{
				Score:        9,
				NumberOfWarn: 1,
			},
		},
		{
			name: "history-only deductions accumulate and floor at zero",
			findings: []finding.Finding{
				historySecretFinding(), historySecretFinding(), historySecretFinding(),
				historySecretFinding(), historySecretFinding(), historySecretFinding(),
				historySecretFinding(), historySecretFinding(), historySecretFinding(),
				historySecretFinding(), historySecretFinding(), historySecretFinding(),
			},
			result: scut.TestReturn{
				Score:        0,
				NumberOfWarn: 12,
			},
		},
		{
			// A current-tree exposure dominates: the presence of history
			// findings alongside it must not soften the score.
			name: "current-tree credential dominates history findings",
			findings: []finding.Finding{
				headSecretFinding(), historySecretFinding(),
			},
			result: scut.TestReturn{
				Score:        0,
				NumberOfWarn: 2,
			},
		},
		{
			// History unavailable must be surfaced, not silently scored as
			// clean.
			name: "history unavailable is reported as info without changing a clean score",
			findings: []finding.Finding{
				{Probe: hasExposedSecret.Probe, Outcome: finding.OutcomeNotAvailable},
				{Probe: hasExposedSecret.Probe, Outcome: finding.OutcomeFalse},
			},
			result: scut.TestReturn{
				Score:        10,
				NumberOfInfo: 1,
			},
		},
		{
			name:     "invalid findings",
			findings: []finding.Finding{},
			result: scut.TestReturn{
				Score: -1,
				Error: sce.ErrScorecardInternal,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dl := scut.TestDetailLogger{}
			got := SecretHygiene(tt.name, tt.findings, &dl)
			scut.ValidateTestReturn(t, tt.name, &tt.result, &got, &dl)
		})
	}
}

func TestSecretHygieneReasonMentionsHistoryGap(t *testing.T) {
	t.Parallel()
	dl := scut.TestDetailLogger{}
	got := SecretHygiene("Secret-Hygiene", []finding.Finding{
		{Probe: hasExposedSecret.Probe, Outcome: finding.OutcomeNotAvailable},
		{Probe: hasExposedSecret.Probe, Outcome: finding.OutcomeFalse},
	}, &dl)

	// The headline reason must state the coverage gap; a 10/10 that silently
	// skipped history would overstate what was verified.
	if !strings.Contains(got.Reason, "git history not inspected") {
		t.Errorf("reason should disclose that history was not inspected, got %q", got.Reason)
	}
}
