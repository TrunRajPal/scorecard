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
	"github.com/ossf/scorecard/v5/probes/hasStaleDependency"
)

// StaleDependencies applies the score policy for the Stale-Dependencies
// check.
//
// SCORING RATIONALE. The score is proportional to the fraction of
// exactly-pinned dependencies that are stale, not to the absolute count.
// An absolute deduction would scale with project size and penalise a large
// project simply for having many dependencies, which says nothing about how
// well it is maintained. A project with 2 stale pins out of 4 is in worse
// shape than one with 3 out of 200.
//
// Dependencies whose staleness could not be determined are excluded from
// both numerator and denominator rather than counted either way. An
// unreachable registry, or a pinned version that has been yanked or
// renamed, is not evidence that the project is out of date -- the same
// principle applied to lookup failures throughout this project.
//
// A project with no exact pins yields OutcomeNotApplicable from the probe
// and an inconclusive result here. That is deliberate: having nothing to
// measure is not the same as being up to date, and awarding a full score
// for it would reward using version ranges rather than assessing them.
func StaleDependencies(name string,
	findings []finding.Finding,
	dl checker.DetailLogger,
) checker.CheckResult {
	expectedProbes := []string{
		hasStaleDependency.Probe,
	}

	if !finding.UniqueProbesEqual(findings, expectedProbes) {
		e := sce.WithMessage(sce.ErrScorecardInternal, "invalid probe results")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	var numStale, numCurrent, numUndetermined int
	for i := range findings {
		f := &findings[i]
		switch f.Outcome {
		case finding.OutcomeNotApplicable:
			return checker.CreateInconclusiveResult(name,
				"no exactly-pinned direct dependencies found to assess")
		case finding.OutcomeTrue:
			numStale++
			checker.LogFinding(dl, f, checker.DetailWarn)
		case finding.OutcomeFalse:
			numCurrent++
		case finding.OutcomeError:
			numUndetermined++
			checker.LogFinding(dl, f, checker.DetailInfo)
		case finding.OutcomeNotAvailable, finding.OutcomeNotSupported:
		}
	}

	assessed := numStale + numCurrent
	if assessed == 0 {
		// Every pin failed to resolve. Reporting a score here would be
		// reporting on nothing.
		return checker.CreateInconclusiveResult(name,
			fmt.Sprintf("staleness could not be determined for any of the %d pinned dependencies",
				numUndetermined))
	}

	score := checker.CreateProportionalScore(numCurrent, assessed)

	reason := fmt.Sprintf("%d of %d exactly-pinned dependencies are at least %d days behind the current release",
		numStale, assessed, hasStaleDependency.StaleThresholdDays)
	if numUndetermined > 0 {
		reason = fmt.Sprintf("%s (%d could not be assessed)", reason, numUndetermined)
	}

	return checker.CreateResultWithScore(name, reason, score)
}
