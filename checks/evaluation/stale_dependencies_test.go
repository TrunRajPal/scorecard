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

package evaluation

import (
	"testing"

	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/hasStaleDependency"
	scut "github.com/ossf/scorecard/v5/utests"
)

func staleFinding() finding.Finding {
	return finding.Finding{Probe: hasStaleDependency.Probe, Outcome: finding.OutcomeTrue}
}

func currentFinding() finding.Finding {
	return finding.Finding{Probe: hasStaleDependency.Probe, Outcome: finding.OutcomeFalse}
}

func undeterminedFinding() finding.Finding {
	return finding.Finding{Probe: hasStaleDependency.Probe, Outcome: finding.OutcomeError}
}

func TestStaleDependencies(t *testing.T) {
	t.Parallel()
	//nolint:govet
	tests := []struct {
		name     string
		findings []finding.Finding
		result   scut.TestReturn
	}{
		{
			// Nothing to measure is inconclusive, not a pass: awarding full
			// marks would reward using ranges rather than assessing pins.
			name:     "no exact pins is inconclusive",
			findings: []finding.Finding{{Probe: hasStaleDependency.Probe, Outcome: finding.OutcomeNotApplicable}},
			result:   scut.TestReturn{Score: -1},
		},
		{
			name:     "all pins current",
			findings: []finding.Finding{currentFinding(), currentFinding()},
			result:   scut.TestReturn{Score: 10},
		},
		{
			name:     "all pins stale",
			findings: []finding.Finding{staleFinding(), staleFinding()},
			result:   scut.TestReturn{Score: 0, NumberOfWarn: 2},
		},
		{
			// Proportional, not absolute: half stale scores half marks.
			name:     "half stale scores proportionally",
			findings: []finding.Finding{staleFinding(), currentFinding()},
			result:   scut.TestReturn{Score: 5, NumberOfWarn: 1},
		},
		{
			// The same absolute number of stale pins in a larger project
			// scores far better, which is the point of proportional scoring.
			name: "one stale pin among many current ones barely moves the score",
			findings: []finding.Finding{
				staleFinding(), currentFinding(), currentFinding(), currentFinding(),
				currentFinding(), currentFinding(), currentFinding(), currentFinding(),
				currentFinding(), currentFinding(),
			},
			result: scut.TestReturn{Score: 9, NumberOfWarn: 1},
		},
		{
			// Undetermined pins are excluded from both numerator and
			// denominator: an unreachable registry is not evidence of
			// staleness, nor of currency.
			name:     "undetermined pins do not affect the score",
			findings: []finding.Finding{currentFinding(), undeterminedFinding()},
			result:   scut.TestReturn{Score: 10, NumberOfInfo: 1},
		},
		{
			name:     "all pins undetermined is inconclusive",
			findings: []finding.Finding{undeterminedFinding(), undeterminedFinding()},
			result:   scut.TestReturn{Score: -1, NumberOfInfo: 2},
		},
		{
			name:     "invalid findings",
			findings: []finding.Finding{},
			result:   scut.TestReturn{Score: -1, Error: sce.ErrScorecardInternal},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dl := scut.TestDetailLogger{}
			got := StaleDependencies(tt.name, tt.findings, &dl)
			scut.ValidateTestReturn(t, tt.name, &tt.result, &got, &dl)
		})
	}
}
