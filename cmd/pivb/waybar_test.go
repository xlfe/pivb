package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/forwardapi"
)

type fakeStatusAgent struct {
	mu     sync.Mutex
	status core.Status
	err    error
	calls  int
}

func (f *fakeStatusAgent) Status(context.Context) (core.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.status, f.err
}

func (f *fakeStatusAgent) set(status core.Status, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.err = status, err
}

func (f *fakeStatusAgent) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// notifyingBuffer signals every completed line so watch tests can wait for an
// emission instead of sleeping.
type notifyingBuffer struct {
	bytes.Buffer
	lines chan struct{}
}

func (b *notifyingBuffer) Write(p []byte) (int, error) {
	n, err := b.Buffer.Write(p)
	for _, value := range p[:n] {
		if value == '\n' {
			b.lines <- struct{}{}
		}
	}
	return n, err
}

func TestFormatWaybarStatus(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	base := core.Status{WIFProvider: testProviderResource, Version: "test"}
	ready := base
	ready.PINCached = true
	ready.PINVerifiedSerial = testSerialA
	signed := ready
	signed.LastSignAlias = "ro"
	signed.LastSignTarget = testTargetRO
	signed.LastSignSerial = testSerialA
	signed.LastSignKeyID = testKidA
	signed.LastSignAt = now.Add(-5 * time.Minute)
	forwarded := signed
	forwarded.PINCached = false
	forwarded.PINVerifiedSerial = 0
	forwarded.LastSignRoute = "zka-workspace-forwarded"
	forwarded.LastSignForward = &forwardapi.ForwardContext{
		ProviderNodeID: strings.Repeat("a", 32), WorkspaceID: strings.Repeat("b", 32), Bundle: "work",
	}

	tests := []struct {
		name        string
		status      core.Status
		err         error
		wantClass   string
		wantTooltip []string
	}{
		{
			name:        "unavailable",
			err:         errors.New("dial unix /run/user/1000/pivb/wif.sock: connect: no such file"),
			wantClass:   "unavailable",
			wantTooltip: []string{"Run: systemctl --user status pivb"},
		},
		{
			name:        "locked",
			status:      base,
			wantClass:   "locked",
			wantTooltip: []string{"PIN not cached"},
		},
		{
			name:      "ready",
			status:    ready,
			wantClass: "ready",
			wantTooltip: []string{
				"PIN cached \u00b7 key 12345678",
				"No mints since unlock",
			},
		},
		{
			name:      "ready after a mint",
			status:    signed,
			wantClass: "ready",
			wantTooltip: []string{
				"Last mint: ro \u2192 " + testTargetRO,
				"Signed 5m ago by key 12345678",
				"Provider: " + testProviderResource,
			},
		},
		{
			name:      "locked origin after a forwarded mint",
			status:    forwarded,
			wantClass: "locked",
			wantTooltip: []string{
				"Last mint (forwarded): ro → " + testTargetRO,
				"Signed remotely 5m ago by YubiKey 12345678",
				"Provider node: " + strings.Repeat("a", 32),
				"Workspace: " + strings.Repeat("b", 32) + " · work",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatWaybarStatus(tt.status, tt.err, now)
			if got.Class != tt.wantClass || got.Alt != tt.wantClass {
				t.Errorf("class/alt = %q/%q, want %q", got.Class, got.Alt, tt.wantClass)
			}
			if got.Text != " pivb" {
				t.Errorf("text = %q, want %q", got.Text, " pivb")
			}
			for _, want := range tt.wantTooltip {
				if !strings.Contains(got.Tooltip, want) {
					t.Errorf("tooltip does not contain %q:\n%s", want, got.Tooltip)
				}
			}
		})
	}
}

func TestAgoText(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{30 * time.Second, "just now"},
		{5 * time.Minute, "5m ago"},
		{61 * time.Minute, "1h01m ago"},
		{3*time.Hour + 7*time.Minute, "3h07m ago"},
	}
	for _, tt := range tests {
		if got := agoText(tt.in); got != tt.want {
			t.Errorf("agoText(%s) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestStatusCommandRejectsBadFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "negative watch", args: []string{"--watch=-1s"}},
		{name: "unknown format", args: []string{"--format", "xml"}},
		{name: "positional argument", args: []string{"extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := &fakeStatusAgent{}
			var out strings.Builder
			if err := statusCommand(agent, tt.args, &out); err == nil {
				t.Fatalf("statusCommand(%q) succeeded, want an error", tt.args)
			}
			if agent.callCount() != 0 {
				t.Errorf("daemon was queried %d times despite invalid flags", agent.callCount())
			}
			if out.String() != "" {
				t.Errorf("stdout = %q, want nothing", out.String())
			}
		})
	}
}

func TestStatusCommandJSON(t *testing.T) {
	status := core.Status{
		PINCached:         true,
		PINVerifiedSerial: testSerialA,
		WIFProvider:       testProviderResource,
		Version:           "test",
	}
	agent := &fakeStatusAgent{status: status}
	var out strings.Builder
	if err := statusCommand(agent, nil, &out); err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out.String(), "\n  \"pin_cached\": true") {
		t.Errorf("single-shot json output is not indented:\n%s", out.String())
	}
	var got core.Status
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("output is not core.Status JSON: %v (%q)", err, out.String())
	}
	if got.PINCached != status.PINCached || got.PINVerifiedSerial != status.PINVerifiedSerial ||
		got.WIFProvider != status.WIFProvider || got.Version != status.Version {
		t.Errorf("decoded status = %+v, want %+v", got, status)
	}
	if !got.LastSignAt.IsZero() {
		t.Errorf("last_sign_at = %v, want it omitted when nothing has been signed", got.LastSignAt)
	}
}

func TestStatusCommandJSONReturnsDaemonError(t *testing.T) {
	agent := &fakeStatusAgent{err: errors.New("daemon down")}
	var out strings.Builder
	if err := statusCommand(agent, nil, &out); err == nil {
		t.Fatal("status succeeded, want the daemon error")
	}
	if out.String() != "" {
		t.Errorf("stdout = %q, want nothing when the daemon is unreachable", out.String())
	}
}

func TestWatchStatusEmitsOnStartAndTick(t *testing.T) {
	agent := &fakeStatusAgent{err: errors.New("daemon down")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	out := &notifyingBuffer{lines: make(chan struct{}, 4)}
	done := make(chan error, 1)
	go func() { done <- watchStatus(ctx, agent, "waybar", out, ticks) }()

	<-out.lines // emitted immediately, before the first tick
	agent.set(core.Status{PINCached: true, PINVerifiedSerial: testSerialA}, nil)
	ticks <- time.Now()
	<-out.lines
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watchStatus: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d emissions, want 2:\n%s", len(lines), out.String())
	}
	var first, second waybarStatus
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if first.Class != "unavailable" {
		t.Errorf("first emission class = %q, want unavailable", first.Class)
	}
	if second.Class != "ready" {
		t.Errorf("second emission class = %q, want ready", second.Class)
	}
}

func TestWatchedJSONReportsUnavailable(t *testing.T) {
	agent := &fakeStatusAgent{err: errors.New("dial failed:\n  connection refused")}
	var out bytes.Buffer
	if err := writeStatus(context.Background(), agent, "json", &out, true); err != nil {
		t.Fatalf("writeStatus: %v", err)
	}
	var got watchedStatusError
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not an error object: %v (%q)", err, out.String())
	}
	if !got.Unavailable {
		t.Errorf("unavailable = false, want true")
	}
	if got.Error != "dial failed: connection refused" {
		t.Errorf("error = %q, want the collapsed single-line message", got.Error)
	}
}
