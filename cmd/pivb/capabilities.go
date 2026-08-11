package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/xlfe/pivb/internal/attachment"
)

type capabilityEnvelope struct {
	Schema                int      `json:"schema"`
	AttachmentProtocols   []int    `json:"attachment_protocols"`
	AttachmentModes       []string `json:"attachment_modes"`
	RouteBindingProtocols []string `json:"route_binding_protocols,omitempty"`
}

func capabilitiesCommand(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "", "output format (json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *format != "json" {
		return errors.New("usage: pivb capabilities --format=json")
	}
	return json.NewEncoder(stdout).Encode(capabilityEnvelope{
		Schema:              1,
		AttachmentProtocols: []int{attachment.ProtocolEnvironment},
		AttachmentModes:     []string{attachment.ModeLocalAllowed, attachment.ModeRouteRequired},
	})
}
