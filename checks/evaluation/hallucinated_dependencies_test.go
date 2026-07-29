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
	"testing"

	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/hasHallucinatedDependency"
	scut "github.com/ossf/scorecard/v5/utests"
)

func TestHallucinatedDependencies(t *testing.T) {
	t.Parallel()
	//nolint:govet
	tests := []struct {
		name     string
		findings []finding.Finding
		result   scut.TestReturn
	}{
		{
			name: "no manifests found",
			findings: []finding.Finding{
				{
					Probe:   hasHallucinatedDependency.Probe,
					Outcome: finding.OutcomeNotApplicable,
				},
			},
			result: scut.TestReturn{
				Score: -1,
			},
		},
		{
			name: "all dependencies exist",
			findings: []finding.Finding{
				{Probe: hasHallucinatedDependency.Probe, Outcome: finding.OutcomeFalse},
				{Probe: hasHallucinatedDependency.Probe, Outcome: finding.OutcomeFalse},
			},
			result: scut.TestReturn{
				Score: 10,
			},
		},
		{
			name: "one hallucinated dependency",
			findings: []finding.Finding{
				{Probe: hasHallucinatedDependency.Probe, Outcome: finding.OutcomeFalse},
				{Probe: hasHallucinatedDependency.Probe, Outcome: finding.OutcomeTrue},
			},
			result: scut.TestReturn{
				Score:        9,
				NumberOfWarn: 1,
			},
		},
		{
			name:     "score floors at zero with many hallucinated dependencies",
			findings: hallucinatedFindings(t, 12),
			result: scut.TestReturn{
				Score:        0,
				NumberOfWarn: 12,
			},
		},
		{
			name: "two graph anomalies deduct one point (half weight of a direct hallucination)",
			findings: []finding.Finding{
				{Probe: hasHallucinatedDependency.Probe, Outcome: finding.OutcomeFalse},
				graphAnomalyFinding(),
				graphAnomalyFinding(),
			},
			result: scut.TestReturn{
				Score:        9,
				NumberOfWarn: 2,
			},
		},
		{
			name: "one graph anomaly alone rounds down to no deduction",
			findings: []finding.Finding{
				{Probe: hasHallucinatedDependency.Probe, Outcome: finding.OutcomeFalse},
				graphAnomalyFinding(),
			},
			result: scut.TestReturn{
				Score:        10,
				NumberOfWarn: 1,
			},
		},
		{
			name: "direct hallucination and graph anomaly combine, not conflated",
			findings: []finding.Finding{
				{Probe: hasHallucinatedDependency.Probe, Outcome: finding.OutcomeTrue},
				graphAnomalyFinding(),
				graphAnomalyFinding(),
			},
			result: scut.TestReturn{
				// 1 direct hallucination (-1) + 2 graph anomalies (-1 at half weight) = 8.
				Score:        8,
				NumberOfWarn: 3,
			},
		},
		{
			name: "lookup error does not affect score",
			findings: []finding.Finding{
				{Probe: hasHallucinatedDependency.Probe, Outcome: finding.OutcomeFalse},
				{Probe: hasHallucinatedDependency.Probe, Outcome: finding.OutcomeError},
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
			got := HallucinatedDependencies(tt.name, tt.findings, &dl)
			scut.ValidateTestReturn(t, tt.name, &tt.result, &got, &dl)
		})
	}
}

func hallucinatedFindings(t *testing.T, n int) []finding.Finding {
	t.Helper()
	findings := make([]finding.Finding, n)
	for i := range findings {
		findings[i] = finding.Finding{
			Probe:   hasHallucinatedDependency.Probe,
			Outcome: finding.OutcomeTrue,
		}
	}
	return findings
}

func graphAnomalyFinding() finding.Finding {
	return finding.Finding{
		Probe:   hasHallucinatedDependency.Probe,
		Outcome: finding.OutcomeTrue,
		Values:  map[string]string{hasHallucinatedDependency.TransientKey: "true"},
	}
}
