package main

import (
	"os"
	"strings"
	"testing"
)

func TestNixWrapperKeepsSystemdEntryPointAndAppendsGnuPGFallback(t *testing.T) {
	flake, err := os.ReadFile("../../flake.nix")
	if err != nil {
		t.Fatal(err)
	}
	text := string(flake)
	for _, required := range []string{"pkgs.makeWrapper", `wrapProgram "$out/bin/pivb"`, "--suffix PATH", "pkgs.gnupg", `--replace-fail '@pivb@' "$out/bin/pivb"`} {
		if !strings.Contains(text, required) {
			t.Fatalf("flake.nix lacks %q", required)
		}
	}
	if strings.Index(text, "substituteInPlace") > strings.Index(text, "wrapProgram") {
		t.Fatal("systemd substitution must retain $out/bin/pivb as the wrapper entry point before wrapping")
	}
	unit, err := os.ReadFile("../../systemd/pivb.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "ExecStart=@pivb@") {
		t.Fatal("systemd unit no longer uses the package-substituted pivb entry point")
	}
}
