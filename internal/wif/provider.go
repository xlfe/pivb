package wif

import (
	"fmt"
	"sort"
	"strings"
)

// AttributeMapping is the fixed provider attribute mapping. Every mapped
// claim is required by the attribute condition or the per-alias principal-set
// bindings; nothing else from the assertion is surfaced.
func AttributeMapping() []string {
	return []string{
		"google.subject=assertion.sub",
		"attribute.alias=assertion.alias",
		"attribute.target=assertion.target",
		"attribute.serial=assertion.serial",
		"attribute.key_id=assertion.key_id",
	}
}

// AttributeMappingFlag renders the mapping as one gcloud --attribute-mapping
// value.
func AttributeMappingFlag() string {
	return strings.Join(AttributeMapping(), ",")
}

// AttributeCondition generates the provider attribute condition from the
// checked-in configuration: exact issuer, exact audience, the pivb subject
// namespace, and an explicit alias-to-target allowlist. Config validation
// restricts every interpolated value to grammars that cannot contain quotes
// or backslashes, so plain CEL single-quoted literals are safe here.
func AttributeCondition(p Provider, aliasTargets map[string]string) (string, error) {
	if len(aliasTargets) == 0 {
		return "", fmt.Errorf("at least one alias is required")
	}
	names := make([]string, 0, len(aliasTargets))
	for name := range aliasTargets {
		names = append(names, name)
	}
	sort.Strings(names)
	pairs := make([]string, 0, len(names))
	for _, name := range names {
		target := aliasTargets[name]
		if target == "" {
			return "", fmt.Errorf("alias %q has no target", name)
		}
		pairs = append(pairs, fmt.Sprintf("  (assertion.alias == '%s' && assertion.target == '%s')", name, target))
	}
	return fmt.Sprintf(
		"assertion.iss == '%s' &&\nassertion.aud == '%s' &&\nassertion.sub.startsWith('%s') &&\n(\n%s\n)",
		p.IssuerURI, p.OIDCAudience(), SubjectPrefix, strings.Join(pairs, " ||\n"),
	), nil
}
