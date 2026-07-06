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

	var numHallucinated, numLookupErrors int
	for i := range findings {
		f := &findings[i]
		switch f.Outcome {
		case finding.OutcomeNotApplicable:
			return checker.CreateInconclusiveResult(name, "no dependency manifests found")
		case finding.OutcomeTrue:
			numHallucinated++
			checker.LogFinding(dl, f, checker.DetailWarn)
		case finding.OutcomeError:
			// A failed registry lookup is not evidence of hallucination --
			// don't conflate the two by scoring it as a finding.
			numLookupErrors++
			checker.LogFinding(dl, f, checker.DetailInfo)
		case finding.OutcomeFalse, finding.OutcomeNotAvailable, finding.OutcomeNotSupported:
		}
	}

	score := checker.MaxResultScore - numHallucinated
	if score < checker.MinResultScore {
		score = checker.MinResultScore
	}

	reason := fmt.Sprintf("%d dependencies not found on their package registry", numHallucinated)
	if numLookupErrors > 0 {
		reason = fmt.Sprintf("%s (%d lookups could not be completed)", reason, numLookupErrors)
	}

	return checker.CreateResultWithScore(name, reason, score)
}
