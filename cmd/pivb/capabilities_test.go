package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilitiesAdvertiseCooperativeAttachmentProtocol(t *testing.T) {
	var stdout, stderr strings.Builder
	if err := capabilitiesCommand([]string{"--format=json"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var got capabilityEnvelope
	if err := json.Unmarshal([]byte(stdout.String()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != 1 || len(got.AttachmentProtocols) != 1 || got.AttachmentProtocols[0] != 1 {
		t.Fatalf("capabilities = %#v", got)
	}
	if len(got.AttachmentModes) != 2 || got.AttachmentModes[1] != "route-required" || len(got.RouteBindingProtocols) != 0 {
		t.Fatalf("capabilities = %#v", got)
	}
}

func TestCapabilitiesRejectOtherFormats(t *testing.T) {
	if err := capabilitiesCommand(nil, new(strings.Builder), new(strings.Builder)); err == nil {
		t.Fatal("capabilities without --format=json succeeded")
	}
}
