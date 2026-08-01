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
)

func TestFormatWaybarStatus(t *testing.T) {
	base := core.Status{ActiveAlias: "ro", TargetEmail: "ro@example.test", Version: "test"}
	tests := []struct {
		name        string
		status      core.Status
		err         error
		wantClass   string
		wantText    string
		wantTooltip string
	}{
		{name: "unavailable", err: errors.New("dial failed"), wantClass: "unavailable", wantText: " pivb", wantTooltip: "systemctl --user status pivb"},
		{name: "locked", status: base, wantClass: "locked", wantText: " ro", wantTooltip: "PIN not cached"},
		{name: "ready", status: withPIN(base), wantClass: "ready", wantText: " ro", wantTooltip: "PIN cached · key 10569470"},
		{name: "active boundary", status: withExpiry(base, 240), wantClass: "active", wantText: " ro · 4m", wantTooltip: "Token expires in 4m"},
		{name: "expiring", status: withExpiry(base, 239), wantClass: "expiring", wantText: " ro · 4m", wantTooltip: "Token expires in 4m"},
		{name: "last second", status: withExpiry(base, 1), wantClass: "expiring", wantText: " ro · 1m", wantTooltip: "Token expires in 1m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatWaybarStatus(tt.status, tt.err)
			if got.Class != tt.wantClass || got.Alt != tt.wantClass {
				t.Fatalf("class/alt = %q/%q, want %q", got.Class, got.Alt, tt.wantClass)
			}
			if got.Text != tt.wantText {
				t.Fatalf("text = %q, want %q", got.Text, tt.wantText)
			}
			if !strings.Contains(got.Tooltip, tt.wantTooltip) {
				t.Fatalf("tooltip %q does not contain %q", got.Tooltip, tt.wantTooltip)
			}
		})
	}
}

func withPIN(status core.Status) core.Status {
	status.PINCached = true
	status.PINVerifiedSerial = 10569470
	return status
}

func withExpiry(status core.Status, seconds int64) core.Status {
	status.TokenExpiresIn = seconds
	return status
}

type queuedStatusAgent struct {
	mu        sync.Mutex
	responses []statusResponse
}

type statusResponse struct {
	status core.Status
	err    error
}

func (f *queuedStatusAgent) Status(context.Context) (core.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	response := statusResponse{}
	if len(f.responses) > 0 {
		response = f.responses[0]
		f.responses = f.responses[1:]
	}
	return response.status, response.err
}

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

func TestWatchStatusImmediateTickAndRecovery(t *testing.T) {
	agent := &queuedStatusAgent{
		responses: []statusResponse{
			{err: errors.New("daemon down")},
			{status: core.Status{ActiveAlias: "deploy", PINCached: true}},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	out := &notifyingBuffer{lines: make(chan struct{}, 2)}
	done := make(chan error, 1)
	go func() { done <- watchStatus(ctx, agent, "waybar", out, ticks) }()
	<-out.lines
	ticks <- time.Now()
	<-out.lines
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines: %q", len(lines), out.String())
	}
	var first, second waybarStatus
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if first.Class != "unavailable" || second.Class != "ready" {
		t.Fatalf("classes = %q, %q", first.Class, second.Class)
	}
}

func TestWatchedJSONReportsUnavailable(t *testing.T) {
	agent := &queuedStatusAgent{responses: []statusResponse{{err: errors.New("secret\nmultiline")}}}
	var out bytes.Buffer
	if err := writeStatus(context.Background(), agent, "json", &out, true); err != nil {
		t.Fatal(err)
	}
	var got watchedStatusError
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Unavailable || got.Error != "secret multiline" {
		t.Fatalf("output = %#v", got)
	}
}
