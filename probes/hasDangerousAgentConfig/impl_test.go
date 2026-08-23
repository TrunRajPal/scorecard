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

package hasDangerousAgentConfig

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
)

func agentFinding(risk checker.AgentConfigRisk, detail string) checker.AgentConfigFinding {
	return checker.AgentConfigFinding{
		Risk:     risk,
		Detail:   detail,
		Location: &checker.File{Path: ".mcp.json"},
	}
}

func Test_Run(t *testing.T) {
	t.Parallel()
	//nolint:govet
	tests := []struct {
		name     string
		raw      *checker.RawResults
		outcomes []finding.Outcome
		wantErr  bool
	}{
		{
			// A repository with no agent configuration must not be credited
			// with a pass. Awarding full marks here would score a project
			// well simply for not using AI tooling, which is not what the
			// check measures.
			name: "no configuration files is not applicable, not a pass",
			raw: &checker.RawResults{
				AgentConfigResults: checker.AgentConfigData{},
			},
			outcomes: []finding.Outcome{finding.OutcomeNotApplicable},
		},
		{
			name: "configuration files present with nothing risky is a pass",
			raw: &checker.RawResults{
				AgentConfigResults: checker.AgentConfigData{
					ConfigFilesFound: 12,
				},
			},
			outcomes: []finding.Outcome{finding.OutcomeFalse},
		},
		{
			name: "unpinned remote execution is reported",
			raw: &checker.RawResults{
				AgentConfigResults: checker.AgentConfigData{
					ConfigFilesFound: 1,
					Findings: []checker.AgentConfigFinding{
						agentFinding(checker.AgentConfigUnpinnedRemoteExec,
							`MCP server "chrome-devtools" runs npx chrome-devtools-mcp@latest`),
					},
				},
			},
			outcomes: []finding.Outcome{finding.OutcomeTrue},
		},
		{
			name: "hidden instruction characters are reported",
			raw: &checker.RawResults{
				AgentConfigResults: checker.AgentConfigData{
					ConfigFilesFound: 3,
					Findings: []checker.AgentConfigFinding{
						agentFinding(checker.AgentConfigHiddenInstruction,
							"U+E0041 in AGENTS.md line 4"),
					},
				},
			},
			outcomes: []finding.Outcome{finding.OutcomeTrue},
		},
		{
			name: "every finding produces its own outcome",
			raw: &checker.RawResults{
				AgentConfigResults: checker.AgentConfigData{
					ConfigFilesFound: 5,
					Findings: []checker.AgentConfigFinding{
						agentFinding(checker.AgentConfigShellExec, "server invokes sh -c"),
						agentFinding(checker.AgentConfigUnpinnedRemoteExec, "uvx pkg@latest"),
						agentFinding(checker.AgentConfigHiddenInstruction, "U+202E in .cursorrules"),
					},
				},
			},
			outcomes: []finding.Outcome{
				finding.OutcomeTrue, finding.OutcomeTrue, finding.OutcomeTrue,
			},
		},
		{
			name:    "nil raw results",
			raw:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, s, err := Run(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(Probe, s); diff != "" {
				t.Errorf("probe name mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(len(tt.outcomes), len(findings)); diff != "" {
				t.Errorf("finding count mismatch (-want +got):\n%s", diff)
			}
			for i := range tt.outcomes {
				if i >= len(findings) {
					break
				}
				if diff := cmp.Diff(tt.outcomes[i], findings[i].Outcome); diff != "" {
					t.Errorf("outcome %d mismatch (-want +got):\n%s", i, diff)
				}
			}
		})
	}
}

// Test_Run_riskIsCarriedToTheEvaluationLayer guards the contract between the
// probe and the scoring policy. DangerousAgentConfig distinguishes a critical
// construct from an unpinned one solely by RiskKey; if the probe stopped
// setting it, every finding would silently be scored as critical.
func Test_Run_riskIsCarriedToTheEvaluationLayer(t *testing.T) {
	t.Parallel()

	raw := &checker.RawResults{
		AgentConfigResults: checker.AgentConfigData{
			ConfigFilesFound: 2,
			Findings: []checker.AgentConfigFinding{
				agentFinding(checker.AgentConfigUnpinnedRemoteExec, "npx pkg@latest"),
				agentFinding(checker.AgentConfigShellExec, "server invokes bash -c"),
			},
		},
	}

	findings, _, err := Run(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		string(checker.AgentConfigUnpinnedRemoteExec),
		string(checker.AgentConfigShellExec),
	}
	for i, w := range want {
		got, ok := findings[i].Values[RiskKey]
		if !ok {
			t.Fatalf("finding %d carries no %q value; the evaluation layer "+
				"would score it as critical by default", i, RiskKey)
		}
		if diff := cmp.Diff(w, got); diff != "" {
			t.Errorf("risk %d mismatch (-want +got):\n%s", i, diff)
		}
	}
}

// Test_Run_detailNeverCarriesDecodedCharacters is the structural half of the
// project's rule that smuggled text is never reproduced into a report. The raw
// layer reports code points; this test fails if a decoded Tags-block or bidi
// character ever reaches a finding message, from where another model could
// read it back.
func Test_Run_detailNeverCarriesDecodedCharacters(t *testing.T) {
	t.Parallel()

	raw := &checker.RawResults{
		AgentConfigResults: checker.AgentConfigData{
			ConfigFilesFound: 1,
			Findings: []checker.AgentConfigFinding{
				agentFinding(checker.AgentConfigHiddenInstruction,
					"U+E0073 U+E0075 U+E0064 in AGENTS.md line 12"),
			},
		},
	}

	findings, _, err := Run(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msg := findings[0].Message
	for _, r := range msg {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			t.Errorf("message reproduces a Unicode Tags character %U: %q", r, msg)
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			t.Errorf("message reproduces a bidirectional override %U: %q", r, msg)
		}
	}
	if !strings.Contains(msg, "U+") {
		t.Errorf("message should report code points, got %q", msg)
	}
}
