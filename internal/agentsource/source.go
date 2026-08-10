// Package agentsource validates and renders the trusted-host-asserted operator
// context attached to fixed-alias agent-session requests. Alias, target, and
// audience remain the authorization inputs. Kind also selects a cooperative
// smart-card recovery throttle; it is not a security boundary because a peer
// with direct access to the WIF socket may omit Source and normalize to Local.
package agentsource

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	KindLocal        = "local-wif"
	KindAgentSession = "agent-session"
	componentMaxLen  = 32
	SessionIDLength  = 32
)

var (
	componentRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)
	sessionIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Source is carried over the trusted-host WIF socket. An omitted JSON source
// is normalized to Local; an explicit source may only describe an agent
// session and is revalidated by the daemon before it reaches notifications.
type Source struct {
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	SessionID string `json:"session_id"`
}

type Label struct {
	Agent   string
	Project string
	Role    string
}

func Local() Source { return Source{Kind: KindLocal} }

func Agent(label, sessionID string) Source {
	return Source{Kind: KindAgentSession, Label: label, SessionID: sessionID}
}

// ParseLabel accepts exactly <agent>:<project>/<role>. Each component is
// bounded independently so it cannot inject terminal control, logs, or
// notification arguments.
func ParseLabel(raw string) (Label, error) {
	agent, rest, ok := strings.Cut(raw, ":")
	if !ok {
		return Label{}, errors.New("source label must have the form <agent>:<project>/<role>")
	}
	project, role, ok := strings.Cut(rest, "/")
	if !ok || strings.Contains(role, "/") {
		return Label{}, errors.New("source label must have the form <agent>:<project>/<role>")
	}
	parts := []struct {
		name  string
		value string
	}{{"agent", agent}, {"project", project}, {"role", role}}
	for _, part := range parts {
		if !componentRE.MatchString(part.value) {
			return Label{}, fmt.Errorf("source label %s must be 1-%d lowercase ASCII letters, digits, dots, underscores, or hyphens and start with a letter", part.name, componentMaxLen)
		}
	}
	return Label{Agent: agent, Project: project, Role: role}, nil
}

func ValidateSessionID(id string) error {
	if !sessionIDRE.MatchString(id) {
		return fmt.Errorf("session ID must be exactly %d lowercase hexadecimal characters", SessionIDLength)
	}
	return nil
}

// Validate applies the daemon-side closed source contract. A zero source is
// retained as a compatibility spelling of local-wif for direct core callers.
func Validate(source Source, alias string) (Source, Label, error) {
	if source == (Source{}) {
		source = Local()
	}
	if source.Kind == KindLocal {
		if source.Label != "" || source.SessionID != "" {
			return Source{}, Label{}, errors.New("local-wif request source must not carry a label or session ID")
		}
		return source, Label{}, nil
	}
	if source.Kind != KindAgentSession {
		return Source{}, Label{}, fmt.Errorf("unsupported request source kind %q", source.Kind)
	}
	label, err := ParseLabel(source.Label)
	if err != nil {
		return Source{}, Label{}, err
	}
	if label.Role != alias {
		return Source{}, Label{}, fmt.Errorf("source label role %q does not match alias %q", label.Role, alias)
	}
	if err := ValidateSessionID(source.SessionID); err != nil {
		return Source{}, Label{}, err
	}
	return source, label, nil
}

func SigningLabel(source Source, alias, target string) string {
	normalized, label, err := Validate(source, alias)
	if err != nil || normalized.Kind == KindLocal {
		return alias + " → " + target + " (local-wif)"
	}
	shortID := normalized.SessionID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	return fmt.Sprintf("agent %s · project %s · role %s\nsession %s\ntarget %s",
		label.Agent, label.Project, label.Role, shortID, target)
}
