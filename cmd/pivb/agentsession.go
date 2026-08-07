package main

import (
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xlfe/pivb/internal/agentsession"
	"github.com/xlfe/pivb/internal/config"
)

func agentSessionCommand(configPath, wifSocket string, args []string) error {
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return errors.New("usage: pivb agent-session --alias <alias> --source-label <agent>:<project>/<role> -- <command> [args...]")
	}
	fs := flag.NewFlagSet("agent-session", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	alias := fs.String("alias", "", "configured alias to delegate")
	sourceLabel := fs.String("source-label", "", "operator context as <agent>:<project>/<role>")
	if err := fs.Parse(args[:separator]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *alias == "" || *sourceLabel == "" || separator+1 >= len(args) {
		return errors.New("usage: pivb agent-session --alias <alias> --source-label <agent>:<project>/<role> -- <command> [args...]")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		return errors.New("XDG_RUNTIME_DIR is not set")
	}
	if err := agentsession.Run(agentsession.Options{
		Config: cfg, Alias: *alias, SourceLabel: *sourceLabel,
		WIFSocket: wifSocket, RuntimeDir: runtimeDir,
		Command: args[separator+1:],
	}); err != nil {
		return err
	}
	return nil
}

func propagateChildExit(exit *agentsession.ChildExitError) {
	if exit.Signal != 0 {
		signal.Reset(exit.Signal)
		_ = syscall.Kill(os.Getpid(), exit.Signal)
		// A blocked or ignored signal must still produce the conventional
		// process status rather than falling through to a successful return.
		time.Sleep(time.Second)
		os.Exit(128 + int(exit.Signal))
	}
	os.Exit(exit.Code)
}
