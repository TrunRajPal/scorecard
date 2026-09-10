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

package checks

import (
	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks/evaluation"
	"github.com/ossf/scorecard/v5/checks/raw"
	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/probes"
	"github.com/ossf/scorecard/v5/probes/zrunner"
)

// CheckStaleDependencies is the registered name for the Stale-Dependencies
// check.
const CheckStaleDependencies = "Stale-Dependencies"

//nolint:gochecknoinits
func init() {
	supportedRequestTypes := []checker.RequestType{
		checker.CommitBased,
		checker.FileBased,
	}
	if err := registerCheck(CheckStaleDependencies, StaleDependencies, supportedRequestTypes); err != nil {
		// This should never happen.
		panic(err)
	}
}

// StaleDependencies runs the Stale-Dependencies check.
func StaleDependencies(c *checker.CheckRequest) checker.CheckResult {
	rawData, err := raw.StaleDependencies(c)
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckStaleDependencies, e)
	}

	// Set the raw results.
	pRawResults := getRawResults(c)
	pRawResults.StaleDependenciesResults = rawData

	// Evaluate the probes.
	findings, err := zrunner.Run(pRawResults, probes.StaleDependencies)
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckStaleDependencies, e)
	}

	// Return the score evaluation.
	ret := evaluation.StaleDependencies(CheckStaleDependencies, findings, c.Dlogger)
	ret.Findings = findings
	return ret
}
