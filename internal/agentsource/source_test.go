package agentsource

import (
	"strings"
	"testing"
)

const testSessionID = "0123456789abcdef0123456789abcdef"

func TestValidateAgentSource(t *testing.T) {
	source, label, err := Validate(Agent("codex:agentic/ro", testSessionID), "ro")
	if err != nil {
		t.Fatal(err)
	}
	if source.Kind != KindAgentSession || label.Agent != "codex" || label.Project != "agentic" || label.Role != "ro" {
		t.Fatalf("validated source = %+v, label = %+v", source, label)
	}
	if got := SigningLabel(source, "ro", "readonly@example.iam.gserviceaccount.com"); !strings.Contains(got, "session 0123456789ab") || strings.Contains(got, testSessionID) {
		t.Fatalf("notification label did not use the short session ID: %q", got)
	}
}

func TestValidateSourceRejectsUnsafeContext(t *testing.T) {
	tests := []struct {
		name   string
		source Source
		alias  string
	}{
		{"unknown kind", Source{Kind: "remote"}, "ro"},
		{"local label", Source{Kind: KindLocal, Label: "x"}, "ro"},
		{"newline", Agent("codex:bad\nproject/ro", testSessionID), "ro"},
		{"missing role", Agent("codex:agentic", testSessionID), "ro"},
		{"wrong role", Agent("codex:agentic/deploy", testSessionID), "ro"},
		{"bad session", Agent("codex:agentic/ro", "short"), "ro"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := Validate(tt.source, tt.alias); err == nil {
				t.Fatalf("Validate(%+v, %q) succeeded", tt.source, tt.alias)
			}
		})
	}
}

func TestZeroSourceIsLocalCompatibilitySpelling(t *testing.T) {
	source, _, err := Validate(Source{}, "ro")
	if err != nil || source != Local() {
		t.Fatalf("Validate(zero) = (%+v, %v), want local-wif", source, err)
	}
}
