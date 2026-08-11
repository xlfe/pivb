package attachment

import (
	"errors"
	"testing"
)

func TestFromEnvironment(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want Context
		err  bool
	}{
		{name: "absent is local", want: LocalAllowed()},
		{name: "protocol one route", env: map[string]string{
			EnvMode: ModeRouteRequired, EnvProtocol: "1", EnvRouteSocket: "/run/user/1000/zka/pivb.sock",
		}, want: RouteRequired(1, "/run/user/1000/zka/pivb.sock")},
		{name: "unsupported protocol two route", env: map[string]string{
			EnvMode: ModeRouteRequired, EnvProtocol: "2", EnvRouteSocket: "/run/user/1000/zka/pivb.sock",
		}, err: true},
		{name: "explicit local", env: map[string]string{EnvMode: ModeLocalAllowed, EnvProtocol: "1"}, want: LocalAllowed()},
		{name: "partial", env: map[string]string{EnvMode: ModeRouteRequired}, err: true},
		{name: "unknown mode", env: map[string]string{EnvMode: "ambient", EnvProtocol: "1"}, err: true},
		{name: "unknown protocol", env: map[string]string{EnvMode: ModeRouteRequired, EnvProtocol: "9", EnvRouteSocket: "/run/route.sock"}, err: true},
		{name: "missing route", env: map[string]string{EnvMode: ModeRouteRequired, EnvProtocol: "1"}, err: true},
		{name: "relative route", env: map[string]string{EnvMode: ModeRouteRequired, EnvProtocol: "1", EnvRouteSocket: "route.sock"}, err: true},
		{name: "unclean route", env: map[string]string{EnvMode: ModeRouteRequired, EnvProtocol: "1", EnvRouteSocket: "/run/../route.sock"}, err: true},
		{name: "local with route", env: map[string]string{EnvMode: ModeLocalAllowed, EnvProtocol: "1", EnvRouteSocket: "/run/route.sock"}, err: true},
		{name: "whitespace is not normalized", env: map[string]string{EnvMode: " route-required", EnvProtocol: "1", EnvRouteSocket: "/run/route.sock"}, err: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := FromEnvironment(func(name string) string { return test.env[name] })
			if test.err {
				var policy *PolicyError
				if !errors.As(err, &policy) {
					t.Fatalf("error = %v, want PolicyError", err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("FromEnvironment = %#v, %v; want %#v", got, err, test.want)
			}
		})
	}
}

func TestWithExplicitRoute(t *testing.T) {
	managed := RouteRequired(1, "/run/managed.sock")
	for _, explicit := range []string{"", managed.RouteSocket} {
		got, err := WithExplicitRoute(managed, explicit)
		if err != nil || got != managed {
			t.Fatalf("WithExplicitRoute(%q) = %#v, %v", explicit, got, err)
		}
	}
	if _, err := WithExplicitRoute(managed, "/run/other.sock"); err == nil {
		t.Fatal("conflicting explicit route succeeded")
	}
	got, err := WithExplicitRoute(LocalAllowed(), "/run/explicit.sock")
	if err != nil || !got.RouteRequired() || got.Protocol != 1 {
		t.Fatalf("local explicit route = %#v, %v", got, err)
	}
}

func TestContextValidateFailsClosedWithPolicyError(t *testing.T) {
	for name, context := range map[string]Context{
		"omitted":             {},
		"unknown protocol":    RouteRequired(2, "/run/route.sock"),
		"local selects route": {Mode: ModeLocalAllowed, Protocol: ProtocolEnvironment, RouteSocket: "/run/route.sock"},
	} {
		t.Run(name, func(t *testing.T) {
			var policyErr *PolicyError
			if err := context.Validate(); !errors.As(err, &policyErr) {
				t.Fatalf("Validate error = %T %v, want PolicyError", err, err)
			}
		})
	}
}
