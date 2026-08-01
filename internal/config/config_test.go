package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `
default_alias = "ro"

[keys.12345678]
broker_sa = "broker-1@example.test"
key_id = "key-1"

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

func TestLoadFleetKeys(t *testing.T) {
	body := strings.Replace(validConfig, `[aliases.ro]`, "[keys.23456789]\nbroker_sa = \"broker-2@example.test\"\nkey_id = \"key-2\"\n\n[aliases.ro]", 1)
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	serials := cfg.YubiKeySerials()
	if len(serials) != 2 || serials[0] != 12345678 || serials[1] != 23456789 {
		t.Fatalf("serials = %v", serials)
	}
	if keys := cfg.KeysBySerial(); keys[12345678] != (Key{BrokerSA: "broker-1@example.test", KeyID: "key-1"}) || keys[23456789] != (Key{BrokerSA: "broker-2@example.test", KeyID: "key-2"}) {
		t.Fatalf("keys = %v", keys)
	}
}

func TestLoadRejectsInvalidFleetKeys(t *testing.T) {
	tests := []struct {
		name, keys, want string
	}{
		{"empty table", "", `[keys.<serial>]`},
		{"zero serial", "[keys.0]\nbroker_sa = \"broker@example.test\"\nkey_id = \"key-1\"\n", "positive integer"},
		{"non-integer serial", "[keys.not-a-serial]\nbroker_sa = \"broker@example.test\"\nkey_id = \"key-1\"\n", "positive integer"},
		{"missing broker SA", "[keys.12345678]\nkey_id = \"key-1\"\n", "keys.12345678.broker_sa"},
		{"missing key id", "[keys.12345678]\nbroker_sa = \"broker@example.test\"\n", "keys.12345678.key_id"},
		{"duplicate key id", "[keys.12345678]\nbroker_sa = \"broker-1@example.test\"\nkey_id = \"same\"\n[keys.23456789]\nbroker_sa = \"broker-2@example.test\"\nkey_id = \"same\"\n", "duplicate key_id"},
		{"duplicate broker SA", "[keys.12345678]\nbroker_sa = \"same@example.test\"\nkey_id = \"key-1\"\n[keys.23456789]\nbroker_sa = \"same@example.test\"\nkey_id = \"key-2\"\n", "duplicate broker_sa"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start := strings.Index(validConfig, "[keys.12345678]")
			end := strings.Index(validConfig, "[aliases.ro]")
			body := validConfig[:start] + tc.keys + "\n" + validConfig[end:]
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadRejectsLegacyKeyShapeWithMigrationHint(t *testing.T) {
	for _, legacy := range []string{"yubikey_serials = [12345678]", `key_id = "key-1"`, `broker_sa = "broker@example.test"`} {
		t.Run(strings.Fields(legacy)[0], func(t *testing.T) {
			body := strings.Replace(validConfig, "[keys.12345678]\nbroker_sa = \"broker-1@example.test\"\nkey_id = \"key-1\"", legacy, 1)
			_, err := Load(writeConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), strings.Fields(legacy)[0]) || !strings.Contains(err.Error(), "[keys.<serial>]") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
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
	body := strings.Replace(validConfig, `broker_sa = "broker-1@example.test"`, "", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), `config key "keys.12345678.broker_sa" is required`) {
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
