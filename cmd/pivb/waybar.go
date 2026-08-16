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
		switch status.LastSignRoute {
		case "zka-workspace-forwarded":
			lines = append(lines, "Last mint (forwarded): "+status.LastSignAlias+" → "+status.LastSignTarget)
			lines = append(lines, fmt.Sprintf("Signed remotely %s by YubiKey %d", agoText(now.Sub(status.LastSignAt)), status.LastSignSerial))
			if status.LastSignForward != nil {
				lines = append(lines, "Provider node: "+status.LastSignForward.ProviderNodeID)
				lines = append(lines, "Workspace: "+status.LastSignForward.WorkspaceID+" · "+status.LastSignForward.Bundle)
			}
		case "zka-workspace-provider":
			lines = append(lines, "Last mint (workspace provider): "+status.LastSignAlias+" → "+status.LastSignTarget)
			lines = append(lines, fmt.Sprintf("Signed %s by local YubiKey %d", agoText(now.Sub(status.LastSignAt)), status.LastSignSerial))
		default:
			lines = append(lines, "Last mint: "+status.LastSignAlias+" → "+status.LastSignTarget)
			lines = append(lines, fmt.Sprintf("Signed %s by key %d", agoText(now.Sub(status.LastSignAt)), status.LastSignSerial))
		}
	} else {
		lines = append(lines, "No mints since unlock")
	}
	if status.Mints != nil {
		lines = append(lines, fmt.Sprintf("Mints: %d/1m %d/5m %d/60m", status.Mints.Total1m, status.Mints.Total5m, status.Mints.Total60m))
	}
	// The window that closes first is the one the operator needs to know about:
	// it is the next mint that will ask for a touch.
	if nearest, left, ok := nearestReuseWindow(status.ReuseWindows, now); ok {
		lines = append(lines, "Window: "+nearest.Alias+" "+windowLeftText(left)+" left")
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

// nearestReuseWindow picks the touch-free window that closes soonest and how
// long it has left. A window already past its end is reported as absent.
func nearestReuseWindow(windows []core.ReuseWindow, now time.Time) (core.ReuseWindow, time.Duration, bool) {
	var nearest core.ReuseWindow
	found := false
	for _, window := range windows {
		if !window.WindowEndsAt.After(now) {
			continue
		}
		if !found || window.WindowEndsAt.Before(nearest.WindowEndsAt) {
			nearest, found = window, true
		}
	}
	if !found {
		return core.ReuseWindow{}, 0, false
	}
	return nearest, nearest.WindowEndsAt.Sub(now), true
}

func windowLeftText(d time.Duration) string {
	seconds := int(d.Round(time.Second) / time.Second)
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	return fmt.Sprintf("%dm%02ds", seconds/60, seconds%60)
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
