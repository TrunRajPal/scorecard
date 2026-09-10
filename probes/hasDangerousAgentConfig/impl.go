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

package hasDangerousAgentConfig

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
	probes.MustRegister(Probe, Run, []checknames.CheckName{checknames.DangerousAgentConfig})
}

//go:embed *.yml
var fs embed.FS

const (
	Probe = "hasDangerousAgentConfig"

	// RiskKey identifies which construct was found, so that consumers can
	// filter by risk without parsing the message text.
	RiskKey = "risk"
)

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	if raw == nil {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	r := raw.AgentConfigResults

	if r.ConfigFilesFound == 0 {
		// No agent configuration files exist. There is nothing to assess.
		//
		// This is NotApplicable rather than a pass, for the same reason the
		// stale-pinning probe treats a project with no exact pins as
		// inconclusive: having nothing to measure is not a clean result, and
		// awarding full marks for it would credit projects simply for not
		// using AI tooling.
		f, err := finding.NewWith(fs, Probe,
			"no AI agent configuration files found to assess", nil, finding.OutcomeNotApplicable)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		return []finding.Finding{*f}, Probe, nil
	}

	if len(r.Findings) == 0 {
		f, err := finding.NewWith(fs, Probe,
			fmt.Sprintf("%d agent configuration file(s) found, no risky constructs detected",
				r.ConfigFilesFound), nil, finding.OutcomeFalse)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		return []finding.Finding{*f}, Probe, nil
	}

	findings := make([]finding.Finding, 0, len(r.Findings))
	for i := range r.Findings {
		af := r.Findings[i]
		f, err := finding.NewWith(fs, Probe, af.Detail, af.Location.Location(), finding.OutcomeTrue)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f.WithValues(map[string]string{
			RiskKey: string(af.Risk),
		}))
	}

	return findings, Probe, nil
}
