package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/wif"
)

func wifCommand(configPath string, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pivb wif <jwks|credentials|provider-condition>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "jwks":
		return wifJWKSCommand(configPath, rest, os.Stdout)
	case "credentials":
		return wifCredentialsCommand(configPath, rest, os.Stdout)
	case "provider-condition":
		return wifProviderConditionCommand(configPath, rest, os.Stdout)
	default:
		return fmt.Errorf("unknown wif subcommand %q (want jwks, credentials, or provider-condition)", sub)
	}
}

// certFlags collects repeated --cert <serial>=<pem-path> arguments.
type certFlags struct {
	paths map[uint32]string
}

func (c *certFlags) String() string { return "" }

func (c *certFlags) Set(value string) error {
	serialText, path, ok := strings.Cut(value, "=")
	if !ok || path == "" {
		return fmt.Errorf("expected <serial>=<pem-path>, got %q", value)
	}
	serial, err := strconv.ParseUint(serialText, 10, 32)
	if err != nil || serial == 0 {
		return fmt.Errorf("--cert serial %q must be a positive integer YubiKey serial", serialText)
	}
	if c.paths == nil {
		c.paths = make(map[uint32]string)
	}
	if previous, dup := c.paths[uint32(serial)]; dup {
		return fmt.Errorf("--cert repeats serial %d (%q and %q)", serial, previous, path)
	}
	c.paths[uint32(serial)] = path
	return nil
}

func wifJWKSCommand(configPath string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("wif jwks", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var certs certFlags
	fs.Var(&certs, "cert", "<serial>=<pem-path>; repeat once per enrolled YubiKey")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("wif jwks takes no positional arguments")
	}
	if len(certs.paths) == 0 {
		return errors.New("wif jwks requires at least one --cert <serial>=<pem-path>")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	parsed := make(map[uint32]*x509.Certificate, len(certs.paths))
	for serial, path := range certs.paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read certificate for YubiKey %d: %w", serial, err)
		}
		cert, err := wif.ParseCertificatePEM(data)
		if err != nil {
			return fmt.Errorf("certificate %q for YubiKey %d: %w", path, serial, err)
		}
		parsed[serial] = cert
	}
	configured := make(map[uint32]string, len(cfg.Keys))
	for serial, key := range cfg.KeysBySerial() {
		configured[serial] = key.JWKKid
	}
	jwks, err := wif.BuildJWKS(parsed, configured)
	if err != nil {
		return err
	}
	out, err := wif.MarshalJWKS(jwks)
	if err != nil {
		return err
	}
	_, err = stdout.Write(out)
	return err
}

func wifCredentialsCommand(configPath string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("wif credentials", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	alias := fs.String("alias", "", "configured alias to generate a credential file for")
	output := fs.String("output", "", "credential file path to write")
	executable := fs.String("executable", "", "absolute stable path to the installed pivb binary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("wif credentials takes no positional arguments")
	}
	if *alias == "" || *output == "" || *executable == "" {
		return errors.New("usage: pivb wif credentials --alias <alias> --output <path> --executable <absolute-path>")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	aliasCfg, ok := cfg.Aliases[*alias]
	if !ok {
		return fmt.Errorf("alias %q is not configured", *alias)
	}
	data, err := wif.CredentialFile(wif.CredentialFileSpec{
		Provider:        cfg.Provider(),
		Alias:           *alias,
		Target:          aliasCfg.Target,
		LifetimeSeconds: aliasCfg.LifetimeS,
		Executable:      *executable,
	})
	if err != nil {
		return err
	}
	outputPath, err := filepath.Abs(*output)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if err := wif.WriteCredentialFile(outputPath, data); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "wrote %s: alias %q impersonates %s for %ds via %s\n",
		outputPath, *alias, aliasCfg.Target, aliasCfg.LifetimeS, *executable)
	return err
}

func wifProviderConditionCommand(configPath string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("wif provider-condition", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("wif provider-condition takes no positional arguments")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	provider := cfg.Provider()
	condition, err := wif.AttributeCondition(provider, cfg.AliasTargets())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout,
		"# provider resource\n%s\n\n"+
			"# external-account audience (credential files, STS)\n%s\n\n"+
			"# OIDC audience (assertion aud claim)\n%s\n\n"+
			"# issuer\n%s\n\n"+
			"# gcloud --attribute-mapping\n%s\n\n"+
			"# gcloud --attribute-condition\n%s\n",
		provider.Resource(),
		provider.ExternalAccountAudience(),
		provider.OIDCAudience(),
		provider.IssuerURI,
		wif.AttributeMappingFlag(),
		condition)
	return err
}
