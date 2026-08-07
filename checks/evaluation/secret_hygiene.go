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
	"github.com/ossf/scorecard/v5/probes/hasExposedSecret"
)

// SecretHygiene applies the score policy for the Secret-Hygiene check.
//
// SCORING RATIONALE -- the two categories are weighted differently, and
// deliberately so.
//
// A credential in the CURRENT TREE scores the minimum immediately, rather
// than deducting per finding. A live credential in version control is an
// active exposure, not a gradable quality attribute: the difference between
// one leaked key and three is not meaningful, because a single one is
// sufficient for compromise. This mirrors how Dangerous-Workflow treats a
// critical pattern. The consequence is that this check is punitive, which
// is only defensible because the detectors are restricted to
// high-confidence structured formats with placeholder filtering -- a false
// positive here costs a project its whole score, which is precisely why
// recall was traded away for precision in checks/raw/secret_hygiene.go.
//
// A credential found only in HISTORY deducts proportionally instead. It is
// not less serious in principle -- the credential is still retrievable by
// anyone who clones the repository -- but it carries genuine observational
// uncertainty that a current-tree finding does not: the actual remediation
// for an exposed credential is ROTATION at the provider, and rotation is
// invisible from inside the repository. A history remnant of a properly
// rotated credential is harmless, and we cannot tell the two apart. Scoring
// it identically to a live current-tree exposure would assert a certainty
// the evidence does not support. This is the same reasoning applied to
// registry rot in the Hallucinated-Dependencies check: where the signal is
// ambiguous, weight it lower and say why.
func SecretHygiene(name string,
	findings []finding.Finding,
	dl checker.DetailLogger,
) checker.CheckResult {
	expectedProbes := []string{
		hasExposedSecret.Probe,
	}

	if !finding.UniqueProbesEqual(findings, expectedProbes) {
		e := sce.WithMessage(sce.ErrScorecardInternal, "invalid probe results")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	var numHeadSecrets, numHistorySecrets int
	historyUnavailable := false

	for i := range findings {
		f := &findings[i]
		switch f.Outcome {
		case finding.OutcomeTrue:
			if f.Values[hasExposedSecret.ScopeKey] == hasExposedSecret.ScopeHistory {
				numHistorySecrets++
			} else {
				numHeadSecrets++
			}
			checker.LogFinding(dl, f, checker.DetailWarn)
		case finding.OutcomeNotAvailable:
			// The history half of the check could not run. Logged so a
			// partial evaluation is visible rather than passing silently.
			historyUnavailable = true
			checker.LogFinding(dl, f, checker.DetailInfo)
		case finding.OutcomeFalse, finding.OutcomeNotApplicable,
			finding.OutcomeNotSupported, finding.OutcomeError:
		}
	}

	score := checker.MaxResultScore
	switch {
	case numHeadSecrets > 0:
		score = checker.MinResultScore
	case numHistorySecrets > 0:
		score = checker.MaxResultScore - numHistorySecrets
		if score < checker.MinResultScore {
			score = checker.MinResultScore
		}
	}

	var reason string
	switch {
	case numHeadSecrets > 0:
		reason = fmt.Sprintf("%d %s exposed in the current tree, %d retrievable only from git history",
			numHeadSecrets, pluralCredentials(numHeadSecrets), numHistorySecrets)
	case numHistorySecrets > 0:
		reason = fmt.Sprintf("no credentials in the current tree, but %d %s still retrievable from git history",
			numHistorySecrets, pluralCredentials(numHistorySecrets))
	default:
		reason = "no exposed credentials detected"
	}
	if historyUnavailable {
		// Stated in the reason, not just the details, because the headline
		// score would otherwise imply coverage the run did not have.
		reason += " (git history not inspected; re-run with --file-mode git for full coverage)"
	}

	return checker.CreateResultWithScore(name, reason, score)
}

func pluralCredentials(n int) string {
	if n == 1 {
		return "credential"
	}
	return "credentials"
}
