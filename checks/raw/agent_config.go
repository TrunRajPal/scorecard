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

// AGENT CONFIGURATION POLICY
//
// Files read by AI coding agents are an instruction channel with the reach
// of code. This check reports structural constructs in them whose presence
// is a matter of fact, never an interpretation of intent.
//
// Two rules govern what is reported:
//
//  1. Attacker-controlled text is never reproduced. A hidden-instruction
//     finding reports code points and offsets, not the decoded characters.
//     Copying smuggled text into a report would move it into the next
//     reader's context -- including another agent's.
//
//  2. Only constructs with an objective test are reported. "Does this file
//     contain a character from the Unicode Tags block?" has an answer.
//     "Are these instructions malicious?" does not, and is out of scope.

package raw

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
)

// agentInstructionFiles are exact filenames, matched case-insensitively at
// any depth, that agents read as natural-language instructions.
var agentInstructionFiles = []string{
	"agents.md",
	"claude.md",
	"gemini.md",
	"copilot-instructions.md",
	".cursorrules",
	".windsurfrules",
	".clinerules",
	".rules",
	".aiderrules",
}

// agentInstructionDirs are directory prefixes whose markdown contents are
// instruction files, e.g. .cursor/rules/*.mdc and .github/instructions/*.md.
var agentInstructionDirs = []string{
	".cursor/rules/",
	".github/instructions/",
	".github/prompts/",
}

// instructionExtensions limits directory-based matching to text formats.
var instructionExtensions = []string{".md", ".mdc", ".markdown", ".txt"}

// mcpConfigFiles are exact filenames holding Model Context Protocol server
// definitions.
var mcpConfigFiles = []string{
	".mcp.json",
	"mcp.json",
	"mcp_config.json",
}

// packageRunners fetch a package and execute it in one step. An MCP server
// launched through one of these runs whatever the registry serves at that
// moment.
var packageRunners = map[string]bool{
	"npx":  true,
	"bunx": true,
	"uvx":  true,
	"pnpx": true,
	"dlx":  true,
}

// shellCommands execute arbitrary text as code, or fetch it to be executed.
var shellCommands = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"cmd": true, "powershell": true, "pwsh": true,
	"curl": true, "wget": true, "eval": true,
}

// AgentConfig collects risky constructs from AI-agent configuration files.
func AgentConfig(c *checker.CheckRequest) (checker.AgentConfigData, error) {
	var results checker.AgentConfigData

	files, err := c.RepoClient.ListFiles(func(string) (bool, error) { return true, nil })
	if err != nil {
		return results, fmt.Errorf("RepoClient.ListFiles: %w", err)
	}

	for _, f := range files {
		kind := classifyAgentConfig(f)
		if kind == agentConfigNone {
			continue
		}
		results.ConfigFilesFound++

		content, err := readRepoFile(c, f)
		if err != nil {
			// An unreadable file is not evidence of a problem. Skip it
			// rather than reporting a finding that cannot be substantiated.
			continue
		}

		if kind == agentConfigMCP {
			results.Findings = append(results.Findings, scanMCPConfig(f, content)...)
		}
		// Instruction files and MCP definitions are both prose-bearing:
		// hidden characters are checked in either.
		results.Findings = append(results.Findings, scanHiddenCharacters(f, content)...)
	}

	return results, nil
}

type agentConfigKind int

const (
	agentConfigNone agentConfigKind = iota
	agentConfigInstruction
	agentConfigMCP
)

// classifyAgentConfig decides whether a repository path is an agent
// configuration file, and of which kind.
func classifyAgentConfig(fullPath string) agentConfigKind {
	lower := strings.ToLower(fullPath)
	base := path.Base(lower)

	for _, name := range mcpConfigFiles {
		if base == name {
			return agentConfigMCP
		}
	}
	for _, name := range agentInstructionFiles {
		if base == name {
			return agentConfigInstruction
		}
	}
	for _, dir := range agentInstructionDirs {
		// Match the directory anywhere in the path so that monorepo
		// subprojects with their own .cursor/rules are covered.
		if !strings.Contains(lower, dir) {
			continue
		}
		for _, ext := range instructionExtensions {
			if strings.HasSuffix(lower, ext) {
				return agentConfigInstruction
			}
		}
	}
	return agentConfigNone
}

// readRepoFile reads a repository file through the client interface.
func readRepoFile(c *checker.CheckRequest, fullPath string) (string, error) {
	rc, err := c.RepoClient.GetFileReader(fullPath)
	if err != nil {
		return "", fmt.Errorf("GetFileReader: %w", err)
	}
	defer rc.Close()

	var sb strings.Builder
	buf := make([]byte, 32*1024)
	for {
		n, err := rc.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
		// Instruction files are prose. Anything past 1 MB is not, and
		// reading further risks pulling a large binary into memory.
		if sb.Len() > 1<<20 {
			break
		}
	}
	return sb.String(), nil
}

// isHiddenInstructionRune reports whether a rune has no legitimate use in
// prose and is a known instruction-smuggling or text-spoofing vector.
//
// Deliberately EXCLUDED: U+200B ZERO WIDTH SPACE, U+200C ZERO WIDTH
// NON-JOINER and U+200D ZERO WIDTH JOINER. These are required orthographic
// characters in Indic, Persian and Khmer scripts. Measuring against real
// repositories showed they appear throughout translated documentation --
// six AGENTS.md translations in one corpus alone -- so treating them as an
// attack signal reports correct translations as malicious.
func isHiddenInstructionRune(r rune) bool {
	switch {
	// Unicode Tags block. Originally for language tagging, deprecated, and
	// with no rendering. Its only current use is smuggling text past human
	// review while remaining fully visible to a model.
	case r >= 0xE0000 && r <= 0xE007F:
		return true
	// Explicit bidirectional overrides and isolates: the Trojan Source
	// technique (CVE-2021-42574), where rendered order differs from parse
	// order. Plain RTL text does not need these -- the bidi algorithm
	// handles it from the characters themselves.
	case r >= 0x202A && r <= 0x202E:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	default:
		return false
	}
}

// scanHiddenCharacters reports hidden-instruction characters by code point
// and line. The characters themselves are never included in the output.
func scanHiddenCharacters(fullPath, content string) []checker.AgentConfigFinding {
	counts := map[rune]int{}
	firstLine := map[rune]int{}

	line := 1
	for _, r := range content {
		if r == '\n' {
			line++
			continue
		}
		if isHiddenInstructionRune(r) {
			counts[r]++
			if _, seen := firstLine[r]; !seen {
				firstLine[r] = line
			}
		}
	}
	if len(counts) == 0 {
		return nil
	}

	// Report once per file, summarising code points, so that a file padded
	// with thousands of hidden characters produces one finding rather than
	// thousands.
	var parts []string
	total, reportLine := 0, 0
	for r, n := range counts {
		parts = append(parts, fmt.Sprintf("U+%04X x%d", r, n))
		total += n
		if reportLine == 0 || firstLine[r] < reportLine {
			reportLine = firstLine[r]
		}
	}
	sortStrings(parts)

	return []checker.AgentConfigFinding{{
		Risk: checker.AgentConfigHiddenInstruction,
		Detail: fmt.Sprintf("%d invisible or bidirectional-override character(s) (%s)",
			total, strings.Join(parts, ", ")),
		Location: &checker.File{
			Path:      fullPath,
			Type:      finding.FileTypeSource,
			Offset:    uint(reportLine),
			EndOffset: uint(reportLine),
		},
	}}
}

// mcpServerEntry is the subset of an MCP server definition this check reads.
type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type mcpConfigFile struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	Servers    map[string]mcpServerEntry `json:"servers"`
}

// scanMCPConfig reports server definitions that execute unpinned remote code
// or invoke a shell.
//
// Definitions using a "url" rather than a "command" are not reported: they
// address a remote service and do not execute code on the developer's
// machine, so they are a different risk that this construct-level check
// cannot assess.
func scanMCPConfig(fullPath, content string) []checker.AgentConfigFinding {
	var cfg mcpConfigFile
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		// Malformed JSON is not a security finding. A file that cannot be
		// parsed also cannot be shown to contain anything.
		return nil
	}

	servers := map[string]mcpServerEntry{}
	for k, v := range cfg.MCPServers {
		servers[k] = v
	}
	for k, v := range cfg.Servers {
		servers[k] = v
	}

	loc := &checker.File{
		Path:   fullPath,
		Type:   finding.FileTypeSource,
		Offset: 1, EndOffset: 1,
	}

	var out []checker.AgentConfigFinding
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sortStrings(names)

	for _, name := range names {
		entry := servers[name]
		if entry.Command == "" {
			continue
		}
		cmd := strings.ToLower(path.Base(entry.Command))

		if shellCommands[cmd] || argsPipeToShell(entry.Args) {
			out = append(out, checker.AgentConfigFinding{
				Risk: checker.AgentConfigShellExec,
				Detail: fmt.Sprintf("MCP server %q launches %q, executing arbitrary commands on the developer's machine",
					name, entry.Command),
				Location: loc,
			})
			continue
		}

		if packageRunners[cmd] {
			if spec, unpinned := unpinnedPackageSpec(entry.Args); unpinned {
				out = append(out, checker.AgentConfigFinding{
					Risk: checker.AgentConfigUnpinnedRemoteExec,
					Detail: fmt.Sprintf("MCP server %q runs %s %s, fetching and executing an unpinned package at launch",
						name, cmd, spec),
					Location: loc,
				})
			}
		}
	}
	return out
}

// argsPipeToShell reports whether any argument pipes content into a shell,
// e.g. "curl https://x | sh".
func argsPipeToShell(args []string) bool {
	for _, a := range args {
		lower := strings.ToLower(a)
		if !strings.Contains(lower, "|") {
			continue
		}
		for cmd := range shellCommands {
			if strings.Contains(lower, "| "+cmd) || strings.Contains(lower, "|"+cmd) {
				return true
			}
		}
	}
	return false
}

// unpinnedPackageSpec finds the package argument passed to a runner and
// reports whether it lacks an exact version pin.
//
// A pin is exact when the spec carries an explicit version after "@" that is
// not the mutable "latest" tag. "@1.2.3" is pinned; "@latest" and a bare
// name are not.
func unpinnedPackageSpec(args []string) (string, bool) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			// Flags such as -y / --yes precede the package spec.
			continue
		}
		spec := a
		// Scoped npm packages start with "@", so the version separator is
		// the LAST "@" and only counts past the first character.
		idx := strings.LastIndex(spec, "@")
		if idx > 0 {
			version := spec[idx+1:]
			if version != "" && !strings.EqualFold(version, "latest") &&
				!strings.EqualFold(version, "next") && !strings.EqualFold(version, "canary") {
				return spec, false
			}
		}
		return spec, true
	}
	return "", false
}

// sortStrings gives findings a deterministic order, so that two runs over
// the same repository produce byte-identical output.
func sortStrings(s []string) {
	sort.Strings(s)
}
