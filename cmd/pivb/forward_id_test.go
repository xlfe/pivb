package main

import (
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/forwardapi"
)

func TestForwardContextAcceptsZKAAttachmentIDLengths(t *testing.T) {
	valid := forwardapi.ForwardContext{
		OriginNodeID: strings.Repeat("a", 32), WorkspaceID: strings.Repeat("b", 32), Bundle: "work",
		ClaimGeneration: 1, ProviderNodeID: strings.Repeat("c", 32), OperationID: strings.Repeat("e", 32),
	}

	tests := []struct {
		name   string
		mutate func(*forwardapi.ForwardContext)
		want   bool
	}{
		{name: "attachment omitted", want: true},
		{name: "24-character deterministic attachment", mutate: func(fc *forwardapi.ForwardContext) {
			fc.ProviderAttachID = "e8707b4725660d82fbc3ca5f"
		}, want: true},
		{name: "32-character random attachment", mutate: func(fc *forwardapi.ForwardContext) {
			fc.ProviderAttachID = strings.Repeat("d", 32)
		}, want: true},
		{name: "23-character attachment", mutate: func(fc *forwardapi.ForwardContext) {
			fc.ProviderAttachID = strings.Repeat("d", 23)
		}},
		{name: "uppercase attachment", mutate: func(fc *forwardapi.ForwardContext) {
			fc.ProviderAttachID = strings.Repeat("D", 24)
		}},
		{name: "24-character origin node", mutate: func(fc *forwardapi.ForwardContext) {
			fc.OriginNodeID = strings.Repeat("a", 24)
		}},
		{name: "24-character workspace", mutate: func(fc *forwardapi.ForwardContext) {
			fc.WorkspaceID = strings.Repeat("b", 24)
		}},
		{name: "24-character provider node", mutate: func(fc *forwardapi.ForwardContext) {
			fc.ProviderNodeID = strings.Repeat("c", 24)
		}},
		{name: "24-character operation", mutate: func(fc *forwardapi.ForwardContext) {
			fc.OperationID = strings.Repeat("e", 24)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := valid
			if test.mutate != nil {
				test.mutate(&context)
			}
			if got := validForwardContext(context); got != test.want {
				t.Errorf("validForwardContext() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestForwardIDValidation(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		forward    bool
		attachment bool
	}{
		{name: "empty", value: ""},
		{name: "23 lowercase hex", value: strings.Repeat("a", 23)},
		{name: "24 lowercase hex", value: "e8707b4725660d82fbc3ca5f", attachment: true},
		{name: "25 lowercase hex", value: strings.Repeat("a", 25)},
		{name: "31 lowercase hex", value: strings.Repeat("a", 31)},
		{name: "32 lowercase hex", value: strings.Repeat("a", 32), forward: true, attachment: true},
		{name: "33 lowercase hex", value: strings.Repeat("a", 33)},
		{name: "24 uppercase hex", value: strings.Repeat("A", 24)},
		{name: "32 uppercase hex", value: strings.Repeat("A", 32)},
		{name: "24 non-hex", value: strings.Repeat("g", 24)},
		{name: "32 non-hex", value: strings.Repeat("g", 32)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validForwardID(test.value); got != test.forward {
				t.Errorf("validForwardID() = %t, want %t", got, test.forward)
			}
			if got := validForwardAttachmentID(test.value); got != test.attachment {
				t.Errorf("validForwardAttachmentID() = %t, want %t", got, test.attachment)
			}
		})
	}
}
