package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	defaultListen   = "127.0.0.1:8642"
	defaultLifetime = 3600
)

type Config struct {
	Keys                 map[string]Key   `toml:"keys"`
	PIVSlot              string           `toml:"piv_slot"`
	PINCache             string           `toml:"pin_cache"`
	NotifyCmd            []string         `toml:"notify_cmd"`
	ListenMetadata       string           `toml:"listen_metadata"`
	DefaultAlias         string           `toml:"default_alias"`
	RemoteAllowedAliases []string         `toml:"remote_allowed_aliases"`
	Aliases              map[string]Alias `toml:"aliases"`
}

type Key struct {
	BrokerSA string `toml:"broker_sa"`
	KeyID    string `toml:"key_id"`
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
		legacy := false
		for _, key := range undecoded {
			name := key.String()
			keys = append(keys, name)
			if name == "yubikey_serials" || name == "key_id" || name == "broker_sa" {
				legacy = true
			}
		}
		sort.Strings(keys)
		if legacy {
			return nil, fmt.Errorf("legacy config key(s) %s are no longer supported; configure each key as [keys.<serial>] with broker_sa and key_id", strings.Join(keys, ", "))
		}
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
	if len(c.Keys) == 0 {
		errs = append(errs, errors.New("config key \"keys\" must contain at least one [keys.<serial>] table"))
	}
	serialNames := make(map[uint32]string, len(c.Keys))
	keyIDs := make(map[string]string, len(c.Keys))
	brokerSAs := make(map[string]string, len(c.Keys))
	for serialName, key := range c.Keys {
		serialValue, err := strconv.ParseUint(serialName, 10, 32)
		if err != nil || serialValue == 0 {
			errs = append(errs, fmt.Errorf("config key %q must use a positive integer YubiKey serial", "keys."+serialName))
			continue
		}
		serial := uint32(serialValue)
		if previous, exists := serialNames[serial]; exists {
			errs = append(errs, fmt.Errorf("config keys %q and %q name the same YubiKey serial", "keys."+previous, "keys."+serialName))
		} else {
			serialNames[serial] = serialName
		}
		brokerSA := strings.TrimSpace(key.BrokerSA)
		if brokerSA == "" {
			errs = append(errs, fmt.Errorf("config key %q is required", "keys."+serialName+".broker_sa"))
		} else if previous, exists := brokerSAs[brokerSA]; exists {
			errs = append(errs, fmt.Errorf("config keys %q and %q contain duplicate broker_sa %q", "keys."+previous+".broker_sa", "keys."+serialName+".broker_sa", brokerSA))
		} else {
			brokerSAs[brokerSA] = serialName
		}
		keyID := strings.TrimSpace(key.KeyID)
		if keyID == "" {
			errs = append(errs, fmt.Errorf("config key %q is required", "keys."+serialName+".key_id"))
			continue
		}
		if previous, exists := keyIDs[keyID]; exists {
			errs = append(errs, fmt.Errorf("config keys %q and %q contain duplicate key_id %q", "keys."+previous+".key_id", "keys."+serialName+".key_id", keyID))
		} else {
			keyIDs[keyID] = serialName
		}
	}
	if c.PIVSlot != "9c" {
		errs = append(errs, fmt.Errorf("config key \"piv_slot\" must be \"9c\", got %q", c.PIVSlot))
	}
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

func (c *Config) KeysBySerial() map[uint32]Key {
	keys := make(map[uint32]Key, len(c.Keys))
	for serialName, key := range c.Keys {
		serial, err := strconv.ParseUint(serialName, 10, 32)
		if err == nil && serial != 0 {
			keys[uint32(serial)] = Key{BrokerSA: strings.TrimSpace(key.BrokerSA), KeyID: strings.TrimSpace(key.KeyID)}
		}
	}
	return keys
}

func (c *Config) YubiKeySerials() []uint32 {
	keys := c.KeysBySerial()
	serials := make([]uint32, 0, len(keys))
	for serial := range keys {
		serials = append(serials, serial)
	}
	sort.Slice(serials, func(i, j int) bool { return serials[i] < serials[j] })
	return serials
}
