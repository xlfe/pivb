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

const statusRequestTimeout = 2 * time.Second

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
		return encoder.Encode(formatWaybarStatus(status, statusErr, time.Now()))
	}
	if statusErr != nil {
		return encoder.Encode(watchedStatusError{Unavailable: true, Error: oneLine(statusErr.Error())})
	}
	return encoder.Encode(status)
}

func formatWaybarStatus(status core.Status, statusErr error, now time.Time) waybarStatus {
	if statusErr != nil {
		return waybarStatus{
			Text:    " pivb",
			Tooltip: "pivb · unavailable\nDaemon is not responding\n" + oneLine(statusErr.Error()) + "\nRun: systemctl --user status pivb",
			Class:   "unavailable",
			Alt:     "unavailable",
		}
	}

	state := "locked"
	icon := ""
	if status.PINCached {
		state = "ready"
		icon = ""
	}

	lines := []string{"pivb · " + state}
	if status.PINCached {
		pin := "PIN cached"
		if status.PINVerifiedSerial != 0 {
			pin += fmt.Sprintf(" · key %d", status.PINVerifiedSerial)
		}
		lines = append(lines, pin)
	} else {
		lines = append(lines, "PIN not cached — run `pivb unlock`")
	}
	if status.LastSignAlias != "" {
		lines = append(lines, "Last mint: "+status.LastSignAlias+" → "+status.LastSignTarget)
		lines = append(lines, fmt.Sprintf("Signed %s by key %d", agoText(now.Sub(status.LastSignAt)), status.LastSignSerial))
	} else {
		lines = append(lines, "No mints since unlock")
	}
	if status.WIFProvider != "" {
		lines = append(lines, "Provider: "+status.WIFProvider)
	}
	if status.Version != "" {
		lines = append(lines, "pivb "+status.Version)
	}

	return waybarStatus{
		Text:    icon + " pivb",
		Tooltip: strings.Join(lines, "\n"),
		Class:   state,
		Alt:     state,
	}
}

func agoText(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh%02dm ago", int(d.Hours()), int(d.Minutes())%60)
	}
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
