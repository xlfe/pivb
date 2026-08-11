package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/xlfe/pivb/internal/agentapi"
	"github.com/xlfe/pivb/internal/agentsession"
	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/cardlease"
	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/forwardapi"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/uds"
	"github.com/xlfe/pivb/internal/version"
	"github.com/xlfe/pivb/internal/wifapi"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		var childExit *agentsession.ChildExitError
		if errors.As(err, &childExit) {
			propagateChildExit(childExit)
		}
		if errors.Is(err, errReported) {
			// subject-token already wrote its machine-readable error to stdout.
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "pivb:", err)
		if errors.Is(err, errPinentryCancelled) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	global := flag.NewFlagSet("pivb", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	defaultConfig, err := config.DefaultPath()
	if err != nil {
		return err
	}
	configPath := global.String("config", defaultConfig, "configuration file")
	controlSocket := global.String("control-socket", runtimeSocketPath("control.sock"), "control Unix socket (status, unlock, lock)")
	wifSocket := global.String("wif-socket", runtimeSocketPath("wif.sock"), "WIF signing Unix socket")
	forwardSocket := global.String("forward-socket", "", "PIVB forwarding provider Unix socket (disabled when empty)")
	cardLeaseSocket := global.String("card-lease-socket", "", "zkad cooperative smart-card lease Unix socket")
	if err := global.Parse(args); err != nil {
		return err
	}
	if global.NArg() == 0 {
		usage(global)
		return errors.New("a command is required")
	}
	cmd, rest := global.Arg(0), global.Args()[1:]
	switch cmd {
	case "version":
		fmt.Println(version.Value)
		return nil
	case "capabilities":
		return capabilitiesCommand(rest, os.Stdout, os.Stderr)
	case "serve":
		if err := rejectProviderCommandAttachment(); err != nil {
			return err
		}
		if len(rest) != 0 {
			return errors.New("serve takes no arguments")
		}
		if *controlSocket == "" || *wifSocket == "" {
			return errors.New("XDG_RUNTIME_DIR is not set; pass --control-socket and --wif-socket explicitly")
		}
		for label, socket := range map[string]string{"control": *controlSocket, "wif": *wifSocket, "forward": *forwardSocket, "card lease": *cardLeaseSocket} {
			if socket != "" && !filepath.IsAbs(socket) {
				return fmt.Errorf("%s socket must be an absolute path", label)
			}
		}
		return serve(*configPath, *controlSocket, *wifSocket, *forwardSocket, *cardLeaseSocket)
	case "subject-token":
		// Machine interface: every outcome is reported as protocol JSON on
		// stdout, including environment and configuration failures.
		return subjectTokenCommand(*configPath, *wifSocket, rest, os.Stdout, os.Stderr)
	case "agent-session":
		return agentSessionCommand(*configPath, *wifSocket, rest)
	case "wif":
		return wifCommand(*configPath, rest)
	}

	if *controlSocket == "" {
		return errors.New("XDG_RUNTIME_DIR is not set; pass --control-socket explicitly")
	}
	if err := rejectProviderCommandAttachment(); err != nil {
		return err
	}
	client := agentapi.NewClient(*controlSocket)
	if cmd == "status" {
		defer client.HTTP.CloseIdleConnections()
		return statusCommand(client, rest, os.Stdout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	switch cmd {
	case "unlock":
		return unlockCommand(ctx, client, rest, os.Stdout)
	case "lock":
		if len(rest) != 0 {
			return errors.New("lock takes no arguments")
		}
		if err := client.Lock(ctx); err != nil {
			return err
		}
		fmt.Println("locked; cached PIN and signing metadata discarded")
	default:
		usage(global)
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

func rejectProviderCommandAttachment() error {
	ctx, err := attachment.FromEnvironment(os.Getenv)
	if err != nil {
		return fmt.Errorf("%s: %v", tokenapi.CodeRouteRequired, err)
	}
	if ctx.RouteRequired() {
		return fmt.Errorf("%s: command is unavailable in a route-required attachment", tokenapi.CodeRouteRequired)
	}
	return nil
}

func serve(configPath, controlSocket, wifSocket, forwardSocket, cardLeaseSocket string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := pivsigner.CheckPCSC(); err != nil {
		return err
	}
	signer := &pivsigner.Hardware{Serials: cfg.YubiKeySerials(), Notify: cfg.NotifyCmd, Logger: logger, GnuPGHome: cfg.GnuPGHome}
	signer.PrimeGnuPGDiagnostics()
	if cardLeaseSocket != "" {
		signer.Lease = cardlease.Client{Socket: cardLeaseSocket}
	}
	daemonCore := core.New(cfg, signer, version.Value)
	control := &agentapi.API{Core: daemonCore}
	signing := &wifapi.API{Core: daemonCore, Logger: logger}
	forwarding := &forwardapi.API{Backend: forwardBackend{core: daemonCore, logger: logger}}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	serverCount := 2
	if forwardSocket != "" {
		serverCount++
	}
	errCh := make(chan error, serverCount)
	go func() { errCh <- uds.Serve(ctx, controlSocket, control.Handler()) }()
	go func() { errCh <- uds.Serve(ctx, wifSocket, signing.Handler()) }()
	if forwardSocket != "" {
		go func() { errCh <- uds.Serve(ctx, forwardSocket, forwarding.Handler()) }()
	}
	logger.Info("pivb serving",
		"control_socket", controlSocket,
		"wif_socket", wifSocket,
		"forward_socket", forwardSocket,
		"card_lease_socket", cardLeaseSocket,
		"wif_provider", cfg.Provider().Resource())

	var exitErr error
	for range serverCount {
		if err := <-errCh; err != nil && exitErr == nil {
			exitErr = err
		}
		// The first server to exit (error or signal) stops its siblings.
		cancel()
	}
	return exitErr
}

func runtimeSocketPath(name string) string {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		return ""
	}
	return filepath.Join(runtimeDir, "pivb", name)
}

func readPIN() ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("unlock requires a terminal for hidden PIN entry")
	}
	fmt.Fprint(os.Stderr, "YubiKey PIV PIN: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read PIN: %w", err)
	}
	return pin, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func usage(fs *flag.FlagSet) {
	fmt.Fprintf(fs.Output(), "usage: pivb [--config path] [--control-socket path] [--wif-socket path] [--forward-socket path] [--card-lease-socket path] <command>\n\ncommands:\n")
	fmt.Fprintln(fs.Output(), "  serve                                    run the networkless signing daemon")
	fmt.Fprintln(fs.Output(), "  unlock [--if-needed] [--pinentry-program p]   verify and cache the PIV PIN")
	fmt.Fprintln(fs.Output(), "  lock                                     drop the cached PIN and signing metadata")
	fmt.Fprintln(fs.Output(), "  status [--watch d] [--format json|waybar]     card-free daemon status")
	fmt.Fprintln(fs.Output(), "  subject-token --alias <alias>            executable credential source (machine interface)")
	fmt.Fprintln(fs.Output(), "  agent-session [--route-socket <path>] --alias <a> --source-label <agent>:<project>/<role> -- <command> [args...]")
	fmt.Fprintln(fs.Output(), "  wif jwks --cert <serial>=<pem> ...       build the uploaded JWKS from enrolled certificates")
	fmt.Fprintln(fs.Output(), "  wif credentials --alias <a> --output <f> --executable <p>   write one credential file")
	fmt.Fprintln(fs.Output(), "  wif provider-condition                   print provider mapping and condition for gcloud")
	fmt.Fprintln(fs.Output(), "  version")
	fmt.Fprintln(fs.Output(), "  capabilities --format=json")
}
