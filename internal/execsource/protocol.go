// Package execsource implements the Google executable credential-source
// environment and stdout protocol shared by pivb's two subject-token helpers.
package execsource

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/xlfe/pivb/internal/wif"
)

const (
	EnvTokenType         = "GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE"
	EnvAudience          = "GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE"
	EnvImpersonatedEmail = "GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL"
	EnvOutputFile        = "GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE"
)

// ErrReported tells a command entry point that a machine-readable error has
// already been written to stdout and no human prefix should be added.
var ErrReported = errors.New("subject-token error already reported on stdout")

type Environment struct {
	Audience          string
	ImpersonatedEmail *string
}

// EnvironmentError identifies which executable-protocol input failed without
// forcing callers to parse a diagnostic string.
type EnvironmentError struct {
	Field  string
	Detail string
}

func (e *EnvironmentError) Error() string { return e.Detail }

type Success struct {
	Version        int    `json:"version"`
	Success        bool   `json:"success"`
	TokenType      string `json:"token_type"`
	IDToken        string `json:"id_token"`
	ExpirationTime int64  `json:"expiration_time"`
}

type Error struct {
	Version int    `json:"version"`
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ReadEnvironment enforces the invariant portion of the executable protocol.
// Audience and optional impersonation values are returned for comparison with
// either configuration or an immutable session relay.
func ReadEnvironment() (Environment, error) {
	if got := os.Getenv(EnvTokenType); got != wif.TokenType {
		return Environment{}, &EnvironmentError{
			Field:  EnvTokenType,
			Detail: fmt.Sprintf("%s is %q; pivb only issues %q", EnvTokenType, got, wif.TokenType),
		}
	}
	audience, present := os.LookupEnv(EnvAudience)
	if !present || audience == "" {
		return Environment{}, &EnvironmentError{
			Field:  EnvAudience,
			Detail: fmt.Sprintf("%s is missing or empty", EnvAudience),
		}
	}
	if value, present := os.LookupEnv(EnvOutputFile); present {
		return Environment{}, &EnvironmentError{
			Field:  EnvOutputFile,
			Detail: fmt.Sprintf("%s is set to %q; remove output_file from the credential configuration", EnvOutputFile, value),
		}
	}
	env := Environment{Audience: audience}
	if email, present := os.LookupEnv(EnvImpersonatedEmail); present {
		env.ImpersonatedEmail = &email
	}
	return env, nil
}

func Report(stdout, stderr io.Writer, prefix, code, message, detail string) error {
	if detail != "" {
		fmt.Fprintln(stderr, prefix+":", detail)
	}
	if err := json.NewEncoder(stdout).Encode(Error{Version: 1, Success: false, Code: code, Message: message}); err != nil {
		return fmt.Errorf("write executable error document: %w", err)
	}
	return ErrReported
}

func WriteSuccess(stdout io.Writer, token string, expirationTime int64) error {
	return json.NewEncoder(stdout).Encode(Success{
		Version:        1,
		Success:        true,
		TokenType:      wif.TokenType,
		IDToken:        token,
		ExpirationTime: expirationTime,
	})
}
