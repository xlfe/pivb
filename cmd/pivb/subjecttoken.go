package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/wif"
	"github.com/xlfe/pivb/internal/wifapi"
)

// errReported signals that subject-token already wrote its machine-readable
// error document to stdout; main must exit nonzero without printing more.
var errReported = errors.New("subject-token error already reported on stdout")

// Environment variables set by Google auth libraries when invoking an
// executable credential source. (The libraries additionally require
// GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1 in the client environment;
// that check is theirs, not ours.)
const (
	envTokenType         = "GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE"
	envAudience          = "GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE"
	envImpersonatedEmail = "GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL"
	envOutputFile        = "GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE"
)

const subjectTokenTimeout = 28 * time.Second

type executableSuccess struct {
	Version        int    `json:"version"`
	Success        bool   `json:"success"`
	TokenType      string `json:"token_type"`
	IDToken        string `json:"id_token"`
	ExpirationTime int64  `json:"expiration_time"`
}

type executableError struct {
	Version int    `json:"version"`
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// subjectTokenCommand implements the executable credential-source protocol.
// stdout carries exactly one JSON document per invocation; operator detail
// goes to stderr and never includes token material.
func subjectTokenCommand(configPath, wifSocket string, args []string, stdout, stderr io.Writer) error {
	report := func(code, message, detail string) error {
		if detail != "" {
			fmt.Fprintln(stderr, "pivb subject-token:", detail)
		}
		enc := json.NewEncoder(stdout)
		if err := enc.Encode(executableError{Version: 1, Success: false, Code: code, Message: message}); err != nil {
			return fmt.Errorf("write executable error document: %w", err)
		}
		return errReported
	}

	fs := flag.NewFlagSet("subject-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	alias := fs.String("alias", "", "configured alias to mint a subject token for")
	if err := fs.Parse(args); err != nil {
		return report(wifapi.CodeEnv, "invalid subject-token invocation", err.Error())
	}
	if fs.NArg() != 0 {
		return report(wifapi.CodeEnv, "invalid subject-token invocation", "subject-token takes no positional arguments")
	}
	if *alias == "" {
		return report(wifapi.CodeEnv, "invalid subject-token invocation", "--alias is required")
	}
	if wifSocket == "" {
		return report(wifapi.CodeEnv, "pivb signing socket location is unknown",
			"XDG_RUNTIME_DIR is not set; pass --wif-socket explicitly")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return report(wifapi.CodeConfig, "pivb configuration is missing or invalid", err.Error())
	}
	aliasCfg, ok := cfg.Aliases[*alias]
	if !ok {
		return report(wifapi.CodeConfig, fmt.Sprintf("alias %q is not configured", *alias), "")
	}

	// The invoking auth library describes the credential it is building.
	// Every value must match this host's pivb configuration; a mismatch means
	// a tampered, stale, or foreign credential file. The daemon repeats these
	// checks; Google's provider condition and IAM bindings remain the
	// authoritative boundary.
	wantAudience := cfg.Provider().ExternalAccountAudience()
	if got := os.Getenv(envTokenType); got != wif.TokenType {
		return report(wifapi.CodeEnv, "credential configuration requests an unsupported subject token type",
			fmt.Sprintf("%s is %q; pivb only issues %q (invoke pivb through a Google auth library credential source)", envTokenType, got, wif.TokenType))
	}
	if got := os.Getenv(envAudience); got != wantAudience {
		return report(wifapi.CodeEnv, "credential configuration audience does not match pivb configuration",
			fmt.Sprintf("%s is %q but this host derives %q; regenerate with `pivb wif credentials`", envAudience, got, wantAudience))
	}
	if got := os.Getenv(envImpersonatedEmail); got != aliasCfg.Target {
		return report(wifapi.CodeEnv, "credential configuration impersonation target does not match pivb configuration",
			fmt.Sprintf("%s is %q but alias %q targets %q; regenerate with `pivb wif credentials`", envImpersonatedEmail, got, *alias, aliasCfg.Target))
	}
	if got := os.Getenv(envOutputFile); got != "" {
		return report(wifapi.CodeEnv, "subject-token output caching is prohibited",
			fmt.Sprintf("%s is set to %q; remove output_file from the credential configuration", envOutputFile, got))
	}

	ctx, cancel := context.WithTimeout(context.Background(), subjectTokenTimeout)
	defer cancel()
	client := wifapi.NewClient(wifSocket)
	defer client.HTTP.CloseIdleConnections()
	resp, err := client.SubjectToken(ctx, wifapi.SubjectTokenRequest{
		Alias:                   *alias,
		ExternalAccountAudience: wantAudience,
		ImpersonatedEmail:       aliasCfg.Target,
	})
	if err != nil {
		var apiErr *wifapi.APIError
		if errors.As(err, &apiErr) {
			detail := apiErr.Message
			if apiErr.Remedy != "" {
				detail += " (remedy: " + apiErr.Remedy + ")"
			}
			return report(apiErr.Code, apiErr.Message, detail)
		}
		return report(wifapi.CodeUnavailable, "pivb daemon is not reachable on the signing socket",
			err.Error()+"; start it with `systemctl --user start pivb`")
	}
	if strings.Count(resp.IDToken, ".") != 2 {
		return report(wifapi.CodeInternal, "daemon returned a malformed subject token", "")
	}

	if err := json.NewEncoder(stdout).Encode(executableSuccess{
		Version:        1,
		Success:        true,
		TokenType:      wif.TokenType,
		IDToken:        resp.IDToken,
		ExpirationTime: resp.ExpirationTime,
	}); err != nil {
		return fmt.Errorf("write executable success document: %w", err)
	}
	return nil
}
