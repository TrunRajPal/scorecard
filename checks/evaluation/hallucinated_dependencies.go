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
	"github.com/ossf/scorecard/v5/probes/hasHallucinatedDependency"
)

// HallucinatedDependencies applies the score policy for the
// Hallucinated-Dependencies check.
func HallucinatedDependencies(name string,
	findings []finding.Finding,
	dl checker.DetailLogger,
) checker.CheckResult {
	expectedProbes := []string{
		hasHallucinatedDependency.Probe,
	}

	if !finding.UniqueProbesEqual(findings, expectedProbes) {
		e := sce.WithMessage(sce.ErrScorecardInternal, "invalid probe results")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	var numHallucinated, numGraphAnomalies, numLookupErrors int
	for i := range findings {
		f := &findings[i]
		switch f.Outcome {
		case finding.OutcomeNotApplicable:
			return checker.CreateInconclusiveResult(name, "no dependency manifests found")
		case finding.OutcomeTrue:
			if f.Values[hasHallucinatedDependency.TransientKey] == "true" {
				numGraphAnomalies++
			} else {
				numHallucinated++
			}
			checker.LogFinding(dl, f, checker.DetailWarn)
		case finding.OutcomeError:
			// A failed registry lookup is not evidence of hallucination --
			// don't conflate the two by scoring it as a finding.
			numLookupErrors++
			checker.LogFinding(dl, f, checker.DetailInfo)
		case finding.OutcomeFalse, finding.OutcomeNotAvailable, finding.OutcomeNotSupported:
		}
	}

	// Graph anomalies (lockfile entries that don't resolve) are weighted at
	// half the severity of direct-manifest hallucinations, not the same
	// weight. A direct hallucination requires a human or AI to have
	// actively typed a specific non-existent name into a manifest -- a
	// deliberate act. A graph anomaly is a categorically less certain
	// signal: our own negative-set evaluation found a real case
	// (rx-virtualtime-compat in Reactive-Extensions/RxJS) where a
	// resolved-graph entry failed to resolve purely from benign registry
	// rot (an unpublished package from years earlier), not tampering or
	// hallucination. Scoring both at full weight would treat that
	// meaningfully weaker signal as equally damning. Integer division
	// (rounded down) keeps the score an integer without a separate
	// rounding policy to justify.
	score := checker.MaxResultScore - numHallucinated - numGraphAnomalies/2
	if score < checker.MinResultScore {
		score = checker.MinResultScore
	}

	reason := fmt.Sprintf("%d direct dependencies not found on their package registry, "+
		"%d resolved-graph anomalies", numHallucinated, numGraphAnomalies)
	if numLookupErrors > 0 {
		reason = fmt.Sprintf("%s (%d lookups could not be completed)", reason, numLookupErrors)
	}

	return checker.CreateResultWithScore(name, reason, score)
}
