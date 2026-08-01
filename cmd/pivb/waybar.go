package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xlfe/pivb/internal/core"
)

const (
	waybarExpiringSeconds = int64(240)
	statusRequestTimeout  = 2 * time.Second
)

type statusAgent interface {
	Status(context.Context) (core.Status, error)
}

type waybarStatus struct {
	Text    string `json:"text"`
	Tooltip string `json:"tooltip"`
	Class   string `json:"class"`
	Alt     string `json:"alt"`
}

type watchedStatusError struct {
	Unavailable bool   `json:"unavailable"`
	Error       string `json:"error"`
}

func statusCommand(client statusAgent, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	watch := fs.Duration("watch", 0, "continuously emit status at this interval")
	format := fs.String("format", "json", "output format: json or waybar")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("status takes no positional arguments")
	}
	if *watch < 0 {
		return errors.New("status --watch must not be negative")
	}
	if *format != "json" && *format != "waybar" {
		return fmt.Errorf("unknown status format %q", *format)
	}

	if *watch == 0 {
		return writeStatus(context.Background(), client, *format, out, false)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(*watch)
	defer ticker.Stop()
	return watchStatus(ctx, client, *format, out, ticker.C)
}

func watchStatus(ctx context.Context, client statusAgent, format string, out io.Writer, ticks <-chan time.Time) error {
	if err := writeStatus(ctx, client, format, out, true); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticks:
			if err := writeStatus(ctx, client, format, out, true); err != nil {
				return err
			}
		}
	}
}

func writeStatus(parent context.Context, client statusAgent, format string, out io.Writer, watching bool) error {
	ctx, cancel := context.WithTimeout(parent, statusRequestTimeout)
	status, statusErr := client.Status(ctx)
	cancel()
	if parent.Err() != nil {
		return nil
	}

	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	if !watching && format == "json" {
		if statusErr != nil {
			return statusErr
		}
		encoder.SetIndent("", "  ")
		return encoder.Encode(status)
	}
	if format == "waybar" {
		return encoder.Encode(formatWaybarStatus(status, statusErr))
	}
	if statusErr != nil {
		return encoder.Encode(watchedStatusError{Unavailable: true, Error: oneLine(statusErr.Error())})
	}
	return encoder.Encode(status)
}

func formatWaybarStatus(status core.Status, statusErr error) waybarStatus {
	if statusErr != nil {
		return waybarStatus{
			Text:    " pivb",
			Tooltip: "pivb · unavailable\nAgent is not responding\n" + oneLine(statusErr.Error()) + "\nRun: systemctl --user status pivb",
			Class:   "unavailable",
			Alt:     "unavailable",
		}
	}

	state := "locked"
	icon := ""
	if status.TokenExpiresIn > 0 {
		state = "active"
		icon = ""
		if status.TokenExpiresIn < waybarExpiringSeconds {
			state = "expiring"
			icon = ""
		}
	} else if status.PINCached {
		state = "ready"
		icon = ""
	}

	alias := status.ActiveAlias
	if alias == "" {
		alias = "unknown"
	}
	text := icon + " " + alias
	if status.TokenExpiresIn > 0 {
		text += " · " + expiryMinutes(status.TokenExpiresIn)
	}

	lines := []string{"pivb · " + state, "Identity: " + alias}
	if status.TargetEmail != "" {
		lines = append(lines, "Account: "+status.TargetEmail)
	}
	if status.ProjectID != "" {
		project := status.ProjectID
		if status.NumericProject != "" {
			project += " (" + status.NumericProject + ")"
		}
		lines = append(lines, "Project: "+project)
	}
	if status.TokenExpiresIn > 0 {
		lines = append(lines, "Token expires in "+expiryMinutes(status.TokenExpiresIn))
	} else {
		lines = append(lines, "No active token")
	}
	if status.PINCached {
		pin := "PIN cached"
		if status.PINVerifiedSerial != 0 {
			pin += fmt.Sprintf(" · key %d", status.PINVerifiedSerial)
		}
		lines = append(lines, pin)
	} else {
		lines = append(lines, "PIN not cached")
	}
	if status.YubiKeySerial != 0 && status.YubiKeySerial != status.PINVerifiedSerial {
		lines = append(lines, fmt.Sprintf("Token signed by key %d", status.YubiKeySerial))
	}
	if status.Version != "" {
		lines = append(lines, "pivb "+status.Version)
	}
	lines = append(lines, "Click for credential actions")

	return waybarStatus{
		Text:    text,
		Tooltip: strings.Join(lines, "\n"),
		Class:   state,
		Alt:     state,
	}
}

func expiryMinutes(seconds int64) string {
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%dm", (seconds+59)/60)
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
