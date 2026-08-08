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

package hasStaleDependency

import (
	"embed"
	"fmt"
	"strconv"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/internal/checknames"
	"github.com/ossf/scorecard/v5/internal/probes"
	"github.com/ossf/scorecard/v5/probes/internal/utils/uerror"
)

func init() {
	probes.MustRegister(Probe, Run, []checknames.CheckName{checknames.StaleDependencies})
}

//go:embed *.yml
var fs embed.FS

const (
	Probe = "hasStaleDependency"
	// StaleThresholdDays is the age at which an exact pin is reported as
	// stale.
	//
	// This is a POLICY CHOICE, not an empirical constant. The reasoning: a
	// model's training cutoff typically precedes its use by roughly 6-18
	// months, so a year is the point at which a pin is more plausibly
	// explained by stale knowledge than by a deliberate compatibility
	// decision. That is a rationale for picking a threshold -- it is not
	// evidence that any individual pin came from a model, and this probe
	// makes no such claim about any finding.
	StaleThresholdDays = 365

	NameKey           = "name"
	EcosystemKey      = "ecosystem"
	PinnedVersionKey  = "pinnedVersion"
	LatestVersionKey  = "latestVersion"
	DaysBehindKey     = "daysBehind"
	VersionsBehindKey = "versionsBehind"
)

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	if raw == nil {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	r := raw.StaleDependenciesResults

	if len(r.Dependencies) == 0 {
		// No exact pins found. This is genuinely not applicable rather than
		// a pass: a project using only version ranges has nothing for this
		// probe to measure, and should not be credited as if it had.
		f, err := finding.NewWith(fs, Probe,
			"no exactly-pinned direct dependencies found to assess", nil, finding.OutcomeNotApplicable)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		return []finding.Finding{*f}, Probe, nil
	}

	var findings []finding.Finding
	for i := range r.Dependencies {
		d := r.Dependencies[i]
		loc := d.Location.Location()

		values := map[string]string{
			NameKey:           d.Name,
			EcosystemKey:      d.Ecosystem,
			PinnedVersionKey:  d.PinnedVersion,
			LatestVersionKey:  d.LatestVersion,
			DaysBehindKey:     strconv.Itoa(d.DaysBehind),
			VersionsBehindKey: strconv.Itoa(d.VersionsBehind),
		}

		switch {
		case d.Error != nil:
			// A registry that could not be reached, or a pin absent from
			// the registry, is not evidence of staleness.
			f, err := finding.NewWith(fs, Probe,
				fmt.Sprintf("could not assess %q on %s: %s", d.Name, d.Ecosystem, *d.Error),
				loc, finding.OutcomeError)
			if err != nil {
				return nil, Probe, fmt.Errorf("create finding: %w", err)
			}
			findings = append(findings, *f.WithValues(values))

		case d.DaysBehind >= StaleThresholdDays:
			f, err := finding.NewWith(fs, Probe,
				fmt.Sprintf("%q is pinned to %s, which is %d days and %d releases behind the current %s",
					d.Name, d.PinnedVersion, d.DaysBehind, d.VersionsBehind, d.LatestVersion),
				loc, finding.OutcomeTrue)
			if err != nil {
				return nil, Probe, fmt.Errorf("create finding: %w", err)
			}
			findings = append(findings, *f.WithValues(values))

		default:
			f, err := finding.NewWith(fs, Probe, "", loc, finding.OutcomeFalse)
			if err != nil {
				return nil, Probe, fmt.Errorf("create finding: %w", err)
			}
			findings = append(findings, *f.WithValues(values))
		}
	}

	return findings, Probe, nil
}
