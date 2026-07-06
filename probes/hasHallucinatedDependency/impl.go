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

package hasHallucinatedDependency

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
	probes.MustRegister(Probe, Run, []checknames.CheckName{checknames.HallucinatedDependencies})
}

//go:embed *.yml
var fs embed.FS

const (
	Probe        = "hasHallucinatedDependency"
	NameKey      = "name"
	EcosystemKey = "ecosystem"
)

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	if raw == nil {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	r := raw.HallucinatedDependenciesResults

	if len(r.Dependencies) == 0 {
		f, err := finding.NewWith(fs, Probe,
			"no dependency manifests found", nil, finding.OutcomeNotApplicable)
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
			NameKey:      d.Name,
			EcosystemKey: d.Ecosystem,
		}

		switch {
		case d.Error != nil:
			f, err := finding.NewWith(fs, Probe,
				fmt.Sprintf("could not verify %q on %s: %s", d.Name, d.Ecosystem, *d.Error),
				loc, finding.OutcomeError)
			if err != nil {
				return nil, Probe, fmt.Errorf("create finding: %w", err)
			}
			f = f.WithValues(values)
			findings = append(findings, *f)
		case d.Exists == nil:
			f, err := finding.NewWith(fs, Probe,
				fmt.Sprintf("%q on %s was not checked", d.Name, d.Ecosystem),
				loc, finding.OutcomeNotAvailable)
			if err != nil {
				return nil, Probe, fmt.Errorf("create finding: %w", err)
			}
			f = f.WithValues(values)
			findings = append(findings, *f)
		case !*d.Exists:
			f, err := finding.NewWith(fs, Probe,
				fmt.Sprintf("dependency %q not found on %s -- possible AI-hallucinated package name", d.Name, d.Ecosystem),
				loc, finding.OutcomeTrue)
			if err != nil {
				return nil, Probe, fmt.Errorf("create finding: %w", err)
			}
			f = f.WithValues(values)
			findings = append(findings, *f)
		default:
			f, err := finding.NewWith(fs, Probe, "", loc, finding.OutcomeFalse)
			if err != nil {
				return nil, Probe, fmt.Errorf("create finding: %w", err)
			}
			f = f.WithValues(values)
			findings = append(findings, *f)
		}
	}

	return findings, Probe, nil
}
