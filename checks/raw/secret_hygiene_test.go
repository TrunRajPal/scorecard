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

package raw

import (
	"fmt"
	"strings"
	"testing"
)

// TEST FIXTURES -- read before editing.
//
// Every credential-shaped string below is SYNTHETIC: each matches a
// detector's *shape* only, and none is or ever was a real credential.
//
// They are assembled from fragments at run time rather than written as
// whole literals. That is not stylistic: these fixtures are realistic
// enough that GitHub's own push protection blocks a push containing them
// as literals, having classified them as live AWS, GitLab and Stripe
// credentials. Splitting the prefix from the body means no complete
// pattern appears in the file text, while the value the detectors see is
// unchanged. Keep this shape when adding fixtures.
var (
	fxAWSKeyID      = "AKIA" + "7TQ2VBRJ4KDNMZLH"
	fxGitHubPAT     = "ghp_" + "9dK2mQ7bZ4vN8xR1tY6wS3jH5gL0pC2fA7eD"
	fxGitHubOAuth   = "gho_" + "9dK2mQ7bZ4vN8xR1tY6wS3jH5gL0pC2fA7eD"
	fxGitHubApp     = "ghs_" + "9dK2mQ7bZ4vN8xR1tY6wS3jH5gL0pC2fA7eD"
	fxGitHubRefresh = "ghr_" + "9dK2mQ7bZ4vN8xR1tY6wS3jH5gL0pC2fA7eD"
	// Deliberately non-repetitive: a run of five identical characters would
	// (correctly) be rejected by the placeholder filter.
	fxGitHubFineGrained = "github_pat_" + "11AB4TZQY0zXwVuTsRqPoN9dK2mQ7bZ4vN8xR1tY6wS3jH5gL0pC2fA7eDqW3xZ"
	fxGitLabPAT         = "glpat" + "-7bZ4vN8xR1tY6wS3jH5g"
	fxSlackToken        = "xoxb" + "-2401849302-4029348203948-Ae4vN8xR1tY6"
	fxSlackWebhook      = "https://hooks.slack.com/services/" + "T0A1B2C3D/B4E5F6G7H/Zx9Yw8Vu7Ts6"
	fxStripeLive        = "sk_live" + "_9dK2mQ7bZ4vN8xR1tY6wS3jH"
	fxGoogleAPIKey      = "AIza" + "SyD9dK2mQ7bZ4vN8xR1tY6wS3jH5gL0pC2x"
	fxNpmToken          = "npm_" + "9dK2mQ7bZ4vN8xR1tY6wS3jH5gL0pC2fA7eD"
	fxPyPIToken         = "pypi" + "-AgEIcHlwaS5vcmc" + strings.Repeat("b", 55)
	fxSendGridKey       = "SG." + strings.Repeat("c", 22) + "." + strings.Repeat("d", 43)
	fxOpenAIKey         = "sk-proj" + "-9dK2mQ7bZ4vN8xR1tY6wS3jH"
	fxAnthropicKey      = "sk-ant" + "-9dK2mQ7bZ4vN8xR1tY6wS3jH"
	fxPEMHeader         = "-----BEGIN " + "PRIVATE KEY-----"
	fxRSAPEMHeader      = "-----BEGIN RSA " + "PRIVATE KEY-----"
)

func TestScanForSecretsDetectsStructuredFormats(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		content    string
		wantID     string
		wantatLine uint
	}{
		{
			name:       "aws access key id",
			content:    "region = us-east-1\nAWS_ACCESS_KEY_ID = " + fxAWSKeyID + "\n",
			wantID:     "aws-access-key-id",
			wantatLine: 2,
		},
		{
			name:       "github classic pat",
			content:    "token: " + fxGitHubPAT + "\n",
			wantID:     "github-personal-access-token",
			wantatLine: 1,
		},
		{
			name:       "gitlab pat",
			content:    "GITLAB_TOKEN=" + fxGitLabPAT + "\n",
			wantID:     "gitlab-personal-access-token",
			wantatLine: 1,
		},
		{
			name:       "stripe live secret key",
			content:    "STRIPE=" + fxStripeLive + "\n",
			wantID:     "stripe-live-secret-key",
			wantatLine: 1,
		},
		{
			name:       "google api key",
			content:    "key = " + fxGoogleAPIKey + "\n",
			wantID:     "google-api-key",
			wantatLine: 1,
		},
		{
			name:       "private key pem header",
			content:    fxRSAPEMHeader + "\nMIIEow==\n",
			wantID:     "private-key-pem",
			wantatLine: 1,
		},
		{
			name:       "slack token",
			content:    "SLACK=" + fxSlackToken + "\n",
			wantID:     "slack-token",
			wantatLine: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			found := scanForSecrets([]byte(tt.content))
			if len(found) == 0 {
				t.Fatalf("expected a detection for %s, got none", tt.wantID)
			}
			var matched bool
			for _, s := range found {
				if s.DetectorID == tt.wantID {
					matched = true
					if s.Line != tt.wantatLine {
						t.Errorf("got line %d, want %d", s.Line, tt.wantatLine)
					}
				}
			}
			if !matched {
				t.Errorf("expected detector %q, got %+v", tt.wantID, found)
			}
		})
	}
}

// TestScanForSecretsRejectsPlaceholders is the most important test here:
// the check is scored, so a false positive silently penalises a project.
func TestScanForSecretsRejectsPlaceholders(t *testing.T) {
	t.Parallel()
	// The first entry is AWS's own documentation key (AKIA…EXAMPLE), which
	// appears verbatim in a great many legitimate repositories.
	placeholders := []string{
		"AWS_ACCESS_KEY_ID = " + "AKIA" + "IOSFODNN7EXAMPLE",
		"aws_key: " + "AKIA" + "EXAMPLE123456789",
		"token: " + "ghp_" + "YOUR_TOKEN_HERE_000000000000000000",
		"key = " + "AIza" + "YOUR-API-KEY-GOES-HERE-REPLACE-ME00",
		"stripe = " + "sk_live" + "_TODOreplacethiswithrealkey00",
	}
	for i := range placeholders {
		line := placeholders[i]
		t.Run(fmt.Sprintf("placeholder_%d", i), func(t *testing.T) {
			t.Parallel()
			if found := scanForSecrets([]byte(line + "\n")); len(found) != 0 {
				t.Errorf("placeholder should not be flagged, got %+v for %q", found, line)
			}
		})
	}
}

// TestPrivateKeyPemRequiresOwnLine covers a false positive found in the
// negative-set run: code that checks for a PEM header is not a PEM key.
func TestPrivateKeyPemRequiresOwnLine(t *testing.T) {
	t.Parallel()

	// Real PEM material: header on its own line.
	realKey := fxRSAPEMHeader + "\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"
	if found := scanForSecrets([]byte(realKey)); len(found) == 0 {
		t.Errorf("a PEM header on its own line should still be detected")
	}

	// Source code that merely mentions the header (verbatim from
	// deis/deis contrib/linode/apply-firewall.py, which the first
	// negative-set run flagged twice).
	mentions := "        if '" + fxRSAPEMHeader + "' in private_key_text:\n" +
		"        elif '-----BEGIN DSA " + "PRIVATE KEY-----' in private_key_text:\n"
	if found := scanForSecrets([]byte(mentions)); len(found) != 0 {
		t.Errorf("code referencing a PEM header is not a key, got %+v", found)
	}
}

func TestScanForSecretsIgnoresOrdinarySource(t *testing.T) {
	t.Parallel()
	// Realistic source that contains high-entropy strings and
	// credential-adjacent words but no actual credential.
	content := `package main

import "fmt"

// integrity hash from a lockfile
const integrity = "sha512-9dK2mQ7bZ4vN8xR1tY6wS3jH5gL0pC2fA7eDqW=="

func main() {
	password := os.Getenv("PASSWORD")
	apiKey := os.Getenv("API_KEY")
	fmt.Println(password, apiKey)
}
`
	if found := scanForSecrets([]byte(content)); len(found) != 0 {
		t.Errorf("ordinary source should produce no findings, got %+v", found)
	}
}

func TestScanForSecretsSkipsBinaryAndOversized(t *testing.T) {
	t.Parallel()

	// A real-shaped credential preceded by a NUL byte: binary content is
	// skipped wholesale.
	binary := append([]byte{0x00, 0x01, 0x02}, []byte(fxAWSKeyID)...)
	if found := scanForSecrets(binary); len(found) != 0 {
		t.Errorf("binary content should be skipped, got %+v", found)
	}

	oversized := []byte(strings.Repeat("a", maxScannedFileSize+1) + "\n" + fxAWSKeyID + "\n")
	if found := scanForSecrets(oversized); len(found) != 0 {
		t.Errorf("oversized content should be skipped, got %+v", found)
	}

	if found := scanForSecrets(nil); len(found) != 0 {
		t.Errorf("empty content should be skipped, got %+v", found)
	}
}

// TestDetectorPrefilterCoversEveryDetector guards the performance gate's
// correctness invariant: if a detector has no corresponding mandatory
// literal in detectorPrefilter, the gate would silently suppress it.
func TestDetectorPrefilterCoversEveryDetector(t *testing.T) {
	t.Parallel()
	samples := map[string]string{
		"aws-access-key-id":            fxAWSKeyID,
		"github-personal-access-token": fxGitHubPAT,
		"github-fine-grained-token":    fxGitHubFineGrained,
		"github-oauth-token":           fxGitHubOAuth,
		"github-app-token":             fxGitHubApp,
		"github-refresh-token":         fxGitHubRefresh,
		"gitlab-personal-access-token": fxGitLabPAT,
		"slack-token":                  fxSlackToken,
		"slack-webhook":                fxSlackWebhook,
		"stripe-live-secret-key":       fxStripeLive,
		"google-api-key":               fxGoogleAPIKey,
		"npm-access-token":             fxNpmToken,
		"pypi-upload-token":            fxPyPIToken,
		"sendgrid-api-key":             fxSendGridKey,
		"openai-api-key":               fxOpenAIKey,
		"anthropic-api-key":            fxAnthropicKey,
		"private-key-pem":              fxPEMHeader,
	}

	for i := range secretDetectors {
		id := secretDetectors[i].id
		sample, ok := samples[id]
		if !ok {
			t.Errorf("detector %q has no sample in this test -- add one so the "+
				"prefilter invariant stays verified", id)
			continue
		}
		if !mayContainSecret(sample) {
			t.Errorf("detector %q: sample is suppressed by detectorPrefilter, so the "+
				"detector can never fire; add its mandatory literal to detectorPrefilter", id)
		}
		if found := scanForSecrets([]byte(sample + "\n")); len(found) == 0 {
			t.Errorf("detector %q: sample produced no detection", id)
		}
	}
}

// TestIsNonProductionPath uses the exact paths that the first negative-set
// run flagged. Each was a vendored dependency, test fixture, or
// documentation example rather than a real leaked credential, and each
// would have scored an established project 0/10.
func TestIsNonProductionPath(t *testing.T) {
	t.Parallel()

	excluded := []string{
		// Vendored dependencies.
		"Godeps/_workspace/src/github.com/coreos/fleet/pkg/tls_test.go",
		"Godeps/_workspace/src/github.com/lib/pq/certs/server.key",
		"node_modules/foo/key.pem",
		"vendor/bar/private.key",
		// Test fixtures.
		"builder/sshd/server_test.go",
		"builder/sshd/test_host_rsa_key_do_not_use",
		"controller/api/tests/test_certificate.py",
		"spec/support/fake_key.pem",
		// Documentation.
		"docs/reference/api-v1.2.rst",
		"docs/using_deis/using-buildpacks.rst",
		"doc/setup.md",
	}
	for _, p := range excluded {
		if !isNonProductionPath(p) {
			t.Errorf("%q should be excluded as non-production material", p)
		}
	}

	// Production paths that must still be scanned: excluding these would
	// gut the check.
	included := []string{
		"config.py",
		"src/main.go",
		"app/settings.py",
		"contrib/linode/apply-firewall.py",
		"wxbot_project_py2.7/config/wechat.conf.bak",
		"README.md",
	}
	for _, p := range included {
		if isNonProductionPath(p) {
			t.Errorf("%q must still be scanned; over-excluding defeats the check", p)
		}
	}
}

func TestIsTemplatePath(t *testing.T) {
	t.Parallel()
	templates := []string{".env.example", "config.yaml.sample", "settings.template", "app.conf.dist"}
	for _, p := range templates {
		if !isTemplatePath(p) {
			t.Errorf("%q should be treated as a template path", p)
		}
	}
	real := []string{".env", "config.yaml", "src/main.go"}
	for _, p := range real {
		if isTemplatePath(p) {
			t.Errorf("%q should NOT be treated as a template path", p)
		}
	}
}
