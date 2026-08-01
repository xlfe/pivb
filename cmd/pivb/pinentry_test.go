package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/core"
)

type fakeUnlockAgent struct {
	status  core.Status
	pin     string
	retries int
}

func (f *fakeUnlockAgent) Status(context.Context) (core.Status, error) { return f.status, nil }
func (f *fakeUnlockAgent) Unlock(_ context.Context, pin string) (int, error) {
	f.pin = pin
	return f.retries, nil
}

func TestReadAssuanReply(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader("D 12%2034%25\nOK\n"))
	got, err := readAssuanReply(scanner)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "12 34%" {
		t.Fatalf("decoded PIN = %q", got)
	}
	zero(got)
}

func TestReadAssuanReplyCancel(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader("ERR 83886179 Operation cancelled <Pinentry>\n"))
	if _, err := readAssuanReply(scanner); !errors.Is(err, errPinentryCancelled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
}

func TestUnlockIfNeededSkipsPrompt(t *testing.T) {
	agent := &fakeUnlockAgent{status: core.Status{PINCached: true}}
	var out strings.Builder
	if err := unlockCommand(context.Background(), agent, []string{"--if-needed"}, &out); err != nil {
		t.Fatal(err)
	}
	if agent.pin != "" {
		t.Fatal("unlock was called despite a cached PIN")
	}
	if out.String() != "already unlocked\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestUnlockWithPinentry(t *testing.T) {
	program := writeFakePinentry(t, `
printf 'OK ready\n'
while IFS= read -r line; do
  case "$line" in
    GETPIN) printf 'D 123456\nOK\n' ;;
    BYE) printf 'OK\n'; exit 0 ;;
    *) printf 'OK\n' ;;
  esac
done
`)
	agent := &fakeUnlockAgent{retries: 3}
	var out strings.Builder
	if err := unlockCommand(context.Background(), agent, []string{"--pinentry-program", program}, &out); err != nil {
		t.Fatal(err)
	}
	if agent.pin != "123456" {
		t.Fatalf("agent received PIN %q", agent.pin)
	}
	if out.String() != "unlocked (PIN retries available: 3)\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestPinentryCancel(t *testing.T) {
	program := writeFakePinentry(t, `
printf 'OK ready\n'
while IFS= read -r line; do
  case "$line" in
    GETPIN) printf 'ERR 83886179 Operation cancelled <Pinentry>\n' ;;
    BYE) exit 0 ;;
    *) printf 'OK\n' ;;
  esac
done
`)
	_, err := readPINFromPinentry(context.Background(), program)
	if !errors.Is(err, errPinentryCancelled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
}

func writeFakePinentry(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pinentry")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
