package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/xlfe/pivb/internal/agentsession"
)

func TestAgentSessionCommandRejectsIncompleteInvocationBeforeConfig(t *testing.T) {
	missingConfig := t.TempDir() + "/missing.toml"
	for _, args := range [][]string{
		nil,
		{"--alias", "ro", "--source-label", "codex:agentic/ro"},
		{"--alias", "ro", "--", "child"},
		{"--source-label", "codex:agentic/ro", "--", "child"},
		{"--alias", "ro", "--source-label", "codex:agentic/ro", "--"},
	} {
		err := agentSessionCommand(missingConfig, "/tmp/wif.sock", args)
		if err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Errorf("args %q error = %v, want usage rejection", args, err)
		}
	}
}

func TestPropagateChildExitHelper(t *testing.T) {
	if os.Getenv("PIVB_TEST_PROPAGATE_SIGNAL") == "1" {
		propagateChildExit(&agentsession.ChildExitError{Code: 128 + int(syscall.SIGTERM), Signal: syscall.SIGTERM})
	}
}

func TestPropagateChildExitReRaisesSignal(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestPropagateChildExitHelper$")
	cmd.Env = append(os.Environ(), "PIVB_TEST_PROPAGATE_SIGNAL=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("subprocess error = %v, want signal exit", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Fatalf("wait status = %#v, want SIGTERM", exitErr.Sys())
	}
}
