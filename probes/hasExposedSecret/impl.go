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
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/internal/checknames"
	"github.com/ossf/scorecard/v5/internal/probes"
	"github.com/ossf/scorecard/v5/probes/internal/utils/uerror"
)

func init() {
	probes.MustRegister(Probe, Run, []checknames.CheckName{checknames.SecretHygiene})
}

//go:embed *.yml
var fs embed.FS

const (
	Probe = "hasExposedSecret"
	// DetectorKey names the rule that matched, e.g. "aws-access-key-id".
	// The credential value itself is never included in a finding -- see the
	// handling policy in checks/raw/secret_hygiene.go.
	DetectorKey = "detector"
	// ScopeKey distinguishes the two failure modes this probe reports.
	// They must never be merged into a single count by a consumer.
	ScopeKey = "scope"
	// ScopeHead marks a credential present in the current tree: an
	// unremediated exposure.
	ScopeHead = "head"
	// ScopeHistory marks a credential absent from the current tree but
	// still retrievable from git history: an incomplete remediation, where
	// a removal commit was made without rewriting history or (observably)
	// rotating the credential.
	ScopeHistory = "history"
)

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	if raw == nil {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	r := raw.SecretHygieneResults

	var findings []finding.Finding

	for i := range r.Secrets {
		s := r.Secrets[i]
		loc := s.Location.Location()

		scope := ScopeHead
		message := fmt.Sprintf(
			"a credential of type %q is present in the current tree -- it is exposed and should be "+
				"treated as compromised until rotated", s.DetectorID)
		if s.InHistory {
			scope = ScopeHistory
			message = fmt.Sprintf(
				"a credential of type %q was removed from the current tree but is still retrievable "+
					"from git history (commit %s) -- removing a credential in a later commit does not "+
					"revoke it, so this is an incomplete remediation rather than a current-tree exposure",
				s.DetectorID, shortSHA(s.CommitSHA))
		}

		f, err := finding.NewWith(fs, Probe, message, loc, finding.OutcomeTrue)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		f = f.WithValues(map[string]string{
			DetectorKey: s.DetectorID,
			ScopeKey:    scope,
		})
		findings = append(findings, *f)
	}

	// Surface the history gap explicitly. Scorecard's default
	// --file-mode archive fetches a tarball with no git history, so the
	// incomplete-remediation half of this check cannot run there. Reporting
	// that as "not available" rather than staying silent keeps a partial
	// evaluation from being mistaken for a clean one.
	if !r.HistoryAvailable {
		f, err := finding.NewWith(fs, Probe,
			"git history was not available, so credentials removed from the current tree but still "+
				"retrievable from history could not be checked; re-run with --file-mode git for full coverage",
			nil, finding.OutcomeNotAvailable)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}

	// No credential detected anywhere that was inspected.
	if len(r.Secrets) == 0 {
		message := "no exposed credentials detected"
		if r.HistoryAvailable {
			message = fmt.Sprintf("no exposed credentials detected in the current tree or in the %d most recent commits",
				r.CommitsScanned)
		}
		f, err := finding.NewWith(fs, Probe, message, nil, finding.OutcomeFalse)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}

	return findings, Probe, nil
}

// shortSHA abbreviates a commit hash for display, matching git's
// conventional 7-character short form.
func shortSHA(sha string) string {
	const shortLen = 7
	if len(sha) <= shortLen {
		return sha
	}
	return sha[:shortLen]
}
