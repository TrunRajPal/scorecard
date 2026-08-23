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

	"github.com/ossf/scorecard/v5/checker"
	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/hasDangerousAgentConfig"
	scut "github.com/ossf/scorecard/v5/utests"
)

func agentRiskFinding(risk checker.AgentConfigRisk) finding.Finding {
	return finding.Finding{
		Probe:   hasDangerousAgentConfig.Probe,
		Outcome: finding.OutcomeTrue,
		Values: map[string]string{
			hasDangerousAgentConfig.RiskKey: string(risk),
		},
	}
}

func TestDangerousAgentConfig(t *testing.T) {
	t.Parallel()
	//nolint:govet
	tests := []struct {
		name     string
		findings []finding.Finding
		result   scut.TestReturn
	}{
		{
			// Nothing to assess is inconclusive, not a pass. A project that
			// uses no AI tooling should not outscore one that uses it safely.
			name: "no configuration files is inconclusive",
			findings: []finding.Finding{
				{Probe: hasDangerousAgentConfig.Probe, Outcome: finding.OutcomeNotApplicable},
			},
			result: scut.TestReturn{Score: -1},
		},
		{
			name: "configuration present with nothing risky scores full marks",
			findings: []finding.Finding{
				{Probe: hasDangerousAgentConfig.Probe, Outcome: finding.OutcomeFalse},
			},
			result: scut.TestReturn{Score: 10},
		},
		{
			// Hidden instructions and local shell execution are treated as
			// critical: both hand control of the developer's machine to
			// content that was never reviewed, so the score goes to the
			// minimum rather than deducting.
			name:     "a hidden instruction scores zero",
			findings: []finding.Finding{agentRiskFinding(checker.AgentConfigHiddenInstruction)},
			result: scut.TestReturn{
				Score:        0,
				NumberOfWarn: 1,
			},
		},
		{
			name:     "shell execution scores zero",
			findings: []finding.Finding{agentRiskFinding(checker.AgentConfigShellExec)},
			result: scut.TestReturn{
				Score:        0,
				NumberOfWarn: 1,
			},
		},
		{
			// Unpinned remote execution is real but weaker: the package is
			// named and the risk is that its contents change, so it deducts
			// proportionally instead of failing outright.
			name:     "one unpinned server deducts two points",
			findings: []finding.Finding{agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec)},
			result: scut.TestReturn{
				Score:        8,
				NumberOfWarn: 1,
			},
		},
		{
			name: "unpinned deductions accumulate",
			findings: []finding.Finding{
				agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec),
				agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec),
				agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec),
			},
			result: scut.TestReturn{
				Score:        4,
				NumberOfWarn: 3,
			},
		},
		{
			// Six unpinned servers would be -2 without the floor, and -1 is
			// reserved for "inconclusive" -- an unclamped score could report
			// a badly failing project as unmeasurable.
			name: "unpinned deductions floor at zero, never negative",
			findings: []finding.Finding{
				agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec),
				agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec),
				agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec),
				agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec),
				agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec),
				agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec),
			},
			result: scut.TestReturn{
				Score:        0,
				NumberOfWarn: 6,
			},
		},
		{
			// A critical construct must dominate: unpinned findings
			// alongside it must not lift the score off the minimum.
			name: "a critical construct dominates unpinned findings",
			findings: []finding.Finding{
				agentRiskFinding(checker.AgentConfigUnpinnedRemoteExec),
				agentRiskFinding(checker.AgentConfigShellExec),
			},
			result: scut.TestReturn{
				Score:        0,
				NumberOfWarn: 2,
			},
		},
		{
			// A finding whose risk value is missing must not be scored as an
			// unpinned deduction. The default branch treats it as critical,
			// which is the safe direction to fail.
			name: "a finding with no risk value is treated as critical",
			findings: []finding.Finding{
				{Probe: hasDangerousAgentConfig.Probe, Outcome: finding.OutcomeTrue},
			},
			result: scut.TestReturn{
				Score:        0,
				NumberOfWarn: 1,
			},
		},
		{
			// A file that could not be read is reported, not scored as clean.
			name: "an error outcome is surfaced as info and does not fail the check",
			findings: []finding.Finding{
				{Probe: hasDangerousAgentConfig.Probe, Outcome: finding.OutcomeError},
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
			got := DangerousAgentConfig(tt.name, tt.findings, &dl)
			scut.ValidateTestReturn(t, tt.name, &tt.result, &got, &dl)
		})
	}
}
