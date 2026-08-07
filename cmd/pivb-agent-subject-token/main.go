// pivb-agent-subject-token is the minimal executable credential source bound
// into an agent sandbox. It knows only the delegated session socket path and
// never loads pivb configuration or links PIV/PCSC support.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/xlfe/pivb/internal/execsource"
	"github.com/xlfe/pivb/internal/sessionapi"
	"github.com/xlfe/pivb/internal/tokenapi"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, execsource.ErrReported) {
			fmt.Fprintln(os.Stderr, "pivb-agent-subject-token:", err)
		}
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	report := func(code, message, detail string) error {
		return execsource.Report(stdout, stderr, "pivb-agent-subject-token", code, message, detail)
	}
	fs := flag.NewFlagSet("pivb-agent-subject-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "", "fixed agent-session Unix socket")
	if err := fs.Parse(args); err != nil {
		return report(tokenapi.CodeEnv, "invalid agent subject-token invocation", err.Error())
	}
	if fs.NArg() != 0 || *socket == "" || !filepath.IsAbs(*socket) {
		return report(tokenapi.CodeEnv, "invalid agent subject-token invocation",
			"exactly one absolute --socket path is required and positional arguments are forbidden")
	}
	env, err := execsource.ReadEnvironment()
	if err != nil {
		return report(tokenapi.CodeEnv, "executable credential environment is invalid", err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionapi.HelperTimeout)
	defer cancel()
	client := sessionapi.NewClient(*socket)
	defer client.HTTP.CloseIdleConnections()
	resp, err := client.SubjectToken(ctx, sessionapi.Request{
		ExternalAccountAudience: env.Audience,
		ImpersonatedEmail:       env.ImpersonatedEmail,
	})
	if err != nil {
		var apiErr *tokenapi.APIError
		if errors.As(err, &apiErr) {
			detail := apiErr.Message
			if apiErr.Remedy != "" {
				detail += " (remedy: " + apiErr.Remedy + ")"
			}
			return report(apiErr.Code, apiErr.Message, detail)
		}
		return report(tokenapi.CodeUnavailable, "pivb agent session is unavailable", err.Error())
	}
	if strings.Count(resp.IDToken, ".") != 2 {
		return report(tokenapi.CodeInternal, "agent-session relay returned a malformed subject token", "")
	}
	if err := execsource.WriteSuccess(stdout, resp.IDToken, resp.ExpirationTime); err != nil {
		return fmt.Errorf("write executable success document: %w", err)
	}
	return nil
}
