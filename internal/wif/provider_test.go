package wif_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/wif"
)

const testDeployTarget = "deployment-sa@example-project-id.iam.gserviceaccount.com"

func TestAttributeMapping(t *testing.T) {
	want := []string{
		"google.subject=assertion.sub",
		"attribute.alias=assertion.alias",
		"attribute.target=assertion.target",
		"attribute.serial=assertion.serial",
		"attribute.key_id=assertion.key_id",
	}
	got := wif.AttributeMapping()
	if !slices.Equal(got, want) {
		t.Fatalf("AttributeMapping() =\n %q\nwant\n %q", got, want)
	}

	wantFlag := "google.subject=assertion.sub," +
		"attribute.alias=assertion.alias," +
		"attribute.target=assertion.target," +
		"attribute.serial=assertion.serial," +
		"attribute.key_id=assertion.key_id"
	if gotFlag := wif.AttributeMappingFlag(); gotFlag != wantFlag {
		t.Fatalf("AttributeMappingFlag() =\n %q\nwant\n %q", gotFlag, wantFlag)
	}
	if gotFlag := wif.AttributeMappingFlag(); gotFlag != strings.Join(want, ",") {
		t.Fatalf("AttributeMappingFlag() is not the mapping joined by commas")
	}
}

func TestAttributeConditionGolden(t *testing.T) {
	got, err := wif.AttributeCondition(testProvider, map[string]string{
		"ro":     testTarget,
		"deploy": testDeployTarget,
	})
	if err != nil {
		t.Fatalf("AttributeCondition: %v", err)
	}

	// Aliases are emitted in sorted order so the generated condition is
	// stable across runs and diffs cleanly against the deployed provider.
	want := `assertion.iss == 'https://auth.example.net/pivb/dep1' &&
assertion.aud == 'https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv' &&
assertion.sub.startsWith('pivb-key:') &&
(
  (assertion.alias == 'deploy' && assertion.target == 'deployment-sa@example-project-id.iam.gserviceaccount.com') ||
  (assertion.alias == 'ro' && assertion.target == 'readonly-sa@example-project-id.iam.gserviceaccount.com')
)`
	if got != want {
		t.Fatalf("AttributeCondition() =\n%s\n\nwant\n%s", got, want)
	}
}

func TestAttributeConditionErrors(t *testing.T) {
	tests := []struct {
		name         string
		aliasTargets map[string]string
		want         []string
	}{
		{"no aliases", map[string]string{}, []string{"at least one alias"}},
		{"nil map", nil, []string{"at least one alias"}},
		{"alias without target", map[string]string{"ro": ""}, []string{"ro", "no target"}},
		{"one alias without target", map[string]string{"ro": testTarget, "deploy": ""}, []string{"deploy", "no target"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := wif.AttributeCondition(testProvider, tc.aliasTargets)
			if got != "" {
				t.Errorf("expected no condition on failure, got:\n%s", got)
			}
			requireErrorContains(t, err, tc.want...)
		})
	}
}
