package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	defaultListen   = "127.0.0.1:8642"
	defaultLifetime = 3600
)

type Config struct {
	YubiKeySerials       []uint32         `toml:"yubikey_serials"`
	PIVSlot              string           `toml:"piv_slot"`
	BrokerSA             string           `toml:"broker_sa"`
	KeyID                string           `toml:"key_id"`
	PINCache             string           `toml:"pin_cache"`
	NotifyCmd            []string         `toml:"notify_cmd"`
	ListenMetadata       string           `toml:"listen_metadata"`
	DefaultAlias         string           `toml:"default_alias"`
	RemoteAllowedAliases []string         `toml:"remote_allowed_aliases"`
	Aliases              map[string]Alias `toml:"aliases"`
}

type Alias struct {
	Cloud            string `toml:"cloud"`
	Target           string `toml:"target"`
	ProjectID        string `toml:"project_id"`
	NumericProjectID string `toml:"numeric_project_id"`
	LifetimeS        int    `toml:"lifetime_s"`
}

func DefaultPath() (string, error) {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "pivb", "config.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve config home: %w", err)
	}
	return filepath.Join(home, ".config", "pivb", "config.toml"), nil
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	md, err := toml.Decode(string(b), &cfg)
	if err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("unknown config key(s): %s", strings.Join(keys, ", "))
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.PIVSlot == "" {
		c.PIVSlot = "9c"
	}
	if c.PINCache == "" {
		c.PINCache = "session"
	}
	if c.ListenMetadata == "" {
		c.ListenMetadata = defaultListen
	}
	if c.NotifyCmd == nil {
		c.NotifyCmd = []string{"notify-send", "pivb"}
	}
	for name, alias := range c.Aliases {
		if alias.Cloud == "" {
			alias.Cloud = "gcp"
		}
		if alias.LifetimeS == 0 {
			alias.LifetimeS = defaultLifetime
		}
		c.Aliases[name] = alias
	}
}

func (c *Config) Validate() error {
	var errs []error
	require := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("config key %q is required", key))
		}
	}
	if len(c.YubiKeySerials) == 0 {
		errs = append(errs, errors.New("config key \"yubikey_serials\" must contain at least one serial"))
	}
	if c.PIVSlot != "9c" {
		errs = append(errs, fmt.Errorf("config key \"piv_slot\" must be \"9c\", got %q", c.PIVSlot))
	}
	require("broker_sa", c.BrokerSA)
	require("key_id", c.KeyID)
	if c.PINCache != "session" && c.PINCache != "never" {
		errs = append(errs, fmt.Errorf("config key \"pin_cache\" must be \"session\" or \"never\", got %q", c.PINCache))
	}
	require("listen_metadata", c.ListenMetadata)
	require("default_alias", c.DefaultAlias)
	if len(c.Aliases) == 0 {
		errs = append(errs, errors.New("config key \"aliases\" must contain at least one alias"))
	}
	if c.DefaultAlias != "" {
		if _, ok := c.Aliases[c.DefaultAlias]; !ok {
			errs = append(errs, fmt.Errorf("config key \"default_alias\" names unknown alias %q", c.DefaultAlias))
		}
	}
	for name, alias := range c.Aliases {
		prefix := "aliases." + name
		if strings.TrimSpace(name) == "" {
			errs = append(errs, errors.New("config alias name must not be empty"))
		}
		require(prefix+".target", alias.Target)
		require(prefix+".project_id", alias.ProjectID)
		if alias.Cloud != "gcp" {
			errs = append(errs, fmt.Errorf("config key %q uses unsupported v1 cloud %q (only \"gcp\" is implemented)", prefix+".cloud", alias.Cloud))
		}
		if alias.LifetimeS < 1 || alias.LifetimeS > 43200 {
			errs = append(errs, fmt.Errorf("config key %q must be between 1 and 43200", prefix+".lifetime_s"))
		}
	}
	for _, name := range c.RemoteAllowedAliases {
		if _, ok := c.Aliases[name]; !ok {
			errs = append(errs, fmt.Errorf("config key \"remote_allowed_aliases\" names unknown alias %q", name))
		}
	}
	return errors.Join(errs...)
}
