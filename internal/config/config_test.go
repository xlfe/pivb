package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `
yubikey_serials = [12345678]
broker_sa = "broker@example.test"
key_id = "key-1"
default_alias = "ro"

[aliases.ro]
target = "ro@example.test"
project_id = "project-1"
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PIVSlot != "9c" || cfg.PINCache != "session" || cfg.ListenMetadata != "127.0.0.1:8642" {
		t.Fatalf("defaults not applied: %#v", cfg)
	}
	if got := cfg.Aliases["ro"].LifetimeS; got != 3600 {
		t.Fatalf("lifetime default = %d, want 3600", got)
	}
	if got := cfg.Aliases["ro"].Cloud; got != "gcp" {
		t.Fatalf("cloud default = %q, want gcp", got)
	}
	if len(cfg.NotifyCmd) != 2 || cfg.NotifyCmd[0] != "notify-send" {
		t.Fatalf("notify default = %#v", cfg.NotifyCmd)
	}
}

func TestLoadDefaultsCloudWithExplicitLifetime(t *testing.T) {
	body := strings.Replace(validConfig, `project_id = "project-1"`, "project_id = \"project-1\"\nlifetime_s = 7200", 1)
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	alias := cfg.Aliases["ro"]
	if alias.Cloud != "gcp" || alias.LifetimeS != 7200 {
		t.Fatalf("alias defaults = %#v, want cloud gcp and lifetime 7200", alias)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.example.toml"))
	if err != nil {
		t.Fatalf("load config.example.toml: %v", err)
	}
	if len(cfg.Aliases) == 0 {
		t.Fatal("config.example.toml contains no aliases")
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	_, err := Load(writeConfig(t, validConfig+"\ntypo_key = true\n"))
	if err == nil || !strings.Contains(err.Error(), "unknown config key(s): aliases.ro.typo_key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadNamesMissingRequiredKey(t *testing.T) {
	body := strings.Replace(validConfig, `broker_sa = "broker@example.test"`, "", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), `config key "broker_sa" is required`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsAliasUnknownKey(t *testing.T) {
	body := strings.Replace(validConfig, `project_id = "project-1"`, "project_id = \"project-1\"\nlifetim_s = 12", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "aliases.ro.lifetim_s") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRemoteAliasesAndLifetime(t *testing.T) {
	body := strings.Replace(validConfig, `default_alias = "ro"`, "default_alias = \"ro\"\nremote_allowed_aliases = [\"missing\"]", 1)
	body = strings.Replace(body, `project_id = "project-1"`, "project_id = \"project-1\"\nlifetime_s = 43201", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "remote_allowed_aliases") || !strings.Contains(err.Error(), "lifetime_s") {
		t.Fatalf("unexpected error: %v", err)
	}
}
