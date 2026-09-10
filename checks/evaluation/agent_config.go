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
	"fmt"

	"github.com/ossf/scorecard/v5/checker"
	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/hasDangerousAgentConfig"
)

// DangerousAgentConfig applies the score policy for the
// Dangerous-Agent-Config check.
//
// SCORING RATIONALE. The two reported constructs differ in kind, not just
// degree, so they are scored differently.
//
// A hidden-instruction character, or an MCP definition invoking a shell,
// scores 0. Both are unambiguous: no legitimate workflow requires a Unicode
// Tags character in a rules file, and an MCP server that launches `bash`
// grants arbitrary local execution to anything that can edit that file.
// There is no proportionality argument to make -- one instance is the whole
// finding.
//
// An unpinned remote execution is a real weakness but a common and often
// deliberate practice, so it deducts rather than zeroes. The deduction is
// per distinct server definition, capped at the floor.
//
// A repository with no agent configuration files is inconclusive rather than
// a pass. Crediting a project for not using AI tooling would make the check
// reward absence, not safety.
func DangerousAgentConfig(name string,
	findings []finding.Finding,
	dl checker.DetailLogger,
) checker.CheckResult {
	expectedProbes := []string{
		hasDangerousAgentConfig.Probe,
	}

	if !finding.UniqueProbesEqual(findings, expectedProbes) {
		e := sce.WithMessage(sce.ErrScorecardInternal, "invalid probe results")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	var numCritical, numUnpinned int
	for i := range findings {
		f := &findings[i]
		switch f.Outcome {
		case finding.OutcomeNotApplicable:
			return checker.CreateInconclusiveResult(name,
				"no AI agent configuration files found to assess")
		case finding.OutcomeTrue:
			switch f.Values[hasDangerousAgentConfig.RiskKey] {
			case string(checker.AgentConfigUnpinnedRemoteExec):
				numUnpinned++
				checker.LogFinding(dl, f, checker.DetailWarn)
			default:
				numCritical++
				checker.LogFinding(dl, f, checker.DetailWarn)
			}
		case finding.OutcomeFalse:
		case finding.OutcomeError, finding.OutcomeNotAvailable, finding.OutcomeNotSupported:
			checker.LogFinding(dl, f, checker.DetailInfo)
		}
	}

	if numCritical > 0 {
		return checker.CreateMinScoreResult(name,
			fmt.Sprintf("%d critical construct(s) in agent configuration: hidden instructions or local shell execution",
				numCritical))
	}

	if numUnpinned == 0 {
		return checker.CreateMaxScoreResult(name,
			"no risky constructs found in agent configuration files")
	}

	// Two points per unpinned server definition, floored at zero.
	score := checker.MaxResultScore - 2*numUnpinned
	if score < checker.MinResultScore {
		score = checker.MinResultScore
	}

	return checker.CreateResultWithScore(name,
		fmt.Sprintf("%d MCP server definition(s) fetch and execute unpinned remote code at launch",
			numUnpinned), score)
}
