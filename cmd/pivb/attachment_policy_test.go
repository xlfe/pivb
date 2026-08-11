package main

import (
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/tokenapi"
)

func TestProviderControlCommandsRejectRouteRequiredAttachment(t *testing.T) {
	t.Setenv(attachment.EnvMode, attachment.ModeRouteRequired)
	t.Setenv(attachment.EnvProtocol, "1")
	t.Setenv(attachment.EnvRouteSocket, "/run/user/1000/zka/pivb/workspace.sock")
	err := rejectProviderCommandAttachment()
	if err == nil || !strings.Contains(err.Error(), tokenapi.CodeRouteRequired) {
		t.Fatalf("route-required provider control error = %v", err)
	}
}

func TestProviderControlCommandsAllowStandaloneAttachment(t *testing.T) {
	t.Setenv(attachment.EnvMode, "")
	t.Setenv(attachment.EnvProtocol, "")
	t.Setenv(attachment.EnvRouteSocket, "")
	if err := rejectProviderCommandAttachment(); err != nil {
		t.Fatalf("standalone provider control rejected: %v", err)
	}
}
