// Package attachment defines the process attachment contract shared by PIVB
// commands and trusted-host APIs. A process with no attachment variables keeps
// the standalone local-card behavior; any partial or malformed managed context
// fails closed.
package attachment

import (
	"path/filepath"
	"strconv"
	"strings"
)

const (
	EnvMode        = "PIVB_ATTACHMENT_MODE"
	EnvRouteSocket = "PIVB_ROUTE_SOCKET"
	EnvProtocol    = "PIVB_ATTACHMENT_PROTOCOL"

	ModeLocalAllowed  = "local-allowed"
	ModeRouteRequired = "route-required"

	ProtocolEnvironment = 1
)

// Context is the validated process attachment. RouteSocket is populated only
// for route-required contexts.
type Context struct {
	Mode        string
	Protocol    int
	RouteSocket string
}

func LocalAllowed() Context {
	return Context{Mode: ModeLocalAllowed, Protocol: ProtocolEnvironment}
}

func RouteRequired(protocol int, route string) Context {
	return Context{Mode: ModeRouteRequired, Protocol: protocol, RouteSocket: route}
}

func (c Context) RouteRequired() bool { return c.Mode == ModeRouteRequired }

// PolicyError is safe to expose as PIVB_ROUTE_REQUIRED. It intentionally
// carries no environment value or route path.
type PolicyError struct{ Message string }

func (e *PolicyError) Error() string { return e.Message }

// FromEnvironment validates the complete versioned attachment tuple.
func FromEnvironment(getenv func(string) string) (Context, error) {
	mode := getenv(EnvMode)
	route := getenv(EnvRouteSocket)
	protocolRaw := getenv(EnvProtocol)
	if mode == "" && route == "" && protocolRaw == "" {
		return LocalAllowed(), nil
	}
	if mode == "" || protocolRaw == "" {
		return Context{}, &PolicyError{Message: "managed PIVB attachment mode and protocol must be provided together"}
	}
	protocol, err := strconv.Atoi(protocolRaw)
	if err != nil || protocol != ProtocolEnvironment {
		return Context{}, &PolicyError{Message: "managed PIVB attachment protocol is unsupported"}
	}
	switch mode {
	case ModeLocalAllowed:
		if route != "" {
			return Context{}, &PolicyError{Message: "local-allowed PIVB attachment must not select a workspace route"}
		}
		return Context{Mode: mode, Protocol: protocol}, nil
	case ModeRouteRequired:
		if err := ValidateRoute(route); err != nil {
			return Context{}, err
		}
		return Context{Mode: mode, Protocol: protocol, RouteSocket: route}, nil
	default:
		return Context{}, &PolicyError{Message: "managed PIVB attachment mode is unsupported"}
	}
}

func ValidateRoute(route string) error {
	if route == "" || !filepath.IsAbs(route) || strings.ContainsRune(route, '\x00') {
		return &PolicyError{Message: "route-required PIVB attachment needs an absolute Unix socket path"}
	}
	// sockaddr_un.sun_path is 108 bytes on supported Linux platforms,
	// including the trailing NUL used for pathname sockets.
	if len(route) >= 108 {
		return &PolicyError{Message: "route-required PIVB attachment socket path is too long"}
	}
	if filepath.Clean(route) != route {
		return &PolicyError{Message: "route-required PIVB attachment socket path is not canonical"}
	}
	return nil
}

// WithExplicitRoute applies agent-session's optional --route-socket. A
// managed route may be omitted or repeated exactly, but never replaced.
func WithExplicitRoute(base Context, explicit string) (Context, error) {
	if explicit != "" {
		if err := ValidateRoute(explicit); err != nil {
			return Context{}, err
		}
	}
	if base.RouteRequired() {
		if explicit != "" && explicit != base.RouteSocket {
			return Context{}, &PolicyError{Message: "explicit PIVB route conflicts with the managed workspace route"}
		}
		return base, nil
	}
	if explicit == "" {
		return base, nil
	}
	return RouteRequired(ProtocolEnvironment, explicit), nil
}

func (c Context) Validate() error {
	switch c.Mode {
	case ModeLocalAllowed:
		if c.Protocol != ProtocolEnvironment || c.RouteSocket != "" {
			return &PolicyError{Message: "invalid local-allowed attachment policy"}
		}
	case ModeRouteRequired:
		if c.Protocol != ProtocolEnvironment {
			return &PolicyError{Message: "invalid route-required attachment protocol"}
		}
		if err := ValidateRoute(c.RouteSocket); err != nil {
			return err
		}
	default:
		return &PolicyError{Message: "attachment policy is required"}
	}
	return nil
}
