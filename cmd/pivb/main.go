package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/xlfe/pivb/internal/agentapi"
	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/gcp"
	"github.com/xlfe/pivb/internal/metadata"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "pivb:", err)
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
	defaultAgent := agentSocketPath()
	configPath := global.String("config", defaultConfig, "configuration file")
	agentPath := global.String("agent", defaultAgent, "agent Unix socket")
	if err := global.Parse(args); err != nil {
		return err
	}
	if global.NArg() == 0 {
		usage(global)
		return errors.New("a command is required")
	}
	cmd, rest := global.Arg(0), global.Args()[1:]
	if cmd == "version" {
		fmt.Println(version.Value)
		return nil
	}
	if *agentPath == "" && cmd != "metadata" {
		return errors.New("XDG_RUNTIME_DIR is not set; pass --agent explicitly")
	}
	if cmd == "serve" {
		if len(rest) != 0 {
			return errors.New("serve takes no arguments")
		}
		return serve(*configPath, *agentPath)
	}
	if cmd == "metadata" {
		return metadataCommand(*agentPath, rest)
	}
	client := agentapi.NewClient(*agentPath)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	switch cmd {
	case "unlock":
		if len(rest) != 0 {
			return errors.New("unlock takes no arguments")
		}
		pin, err := readPIN()
		if err != nil {
			return err
		}
		defer zero(pin)
		retries, err := client.Unlock(ctx, string(pin))
		if err != nil {
			return err
		}
		fmt.Printf("unlocked (PIN retries available: %d)\n", retries)
	case "lock":
		if len(rest) != 0 {
			return errors.New("lock takes no arguments")
		}
		if err := client.Lock(ctx); err != nil {
			return err
		}
		fmt.Println("locked; cached PIN and tokens discarded")
	case "use":
		if len(rest) != 1 {
			return errors.New("usage: pivb use <alias>")
		}
		token, err := client.Use(ctx, rest[0])
		if err != nil {
			return err
		}
		fmt.Printf("now serving %s until %s\n", token.TargetEmail, token.ExpiresAt.Local().Format(time.RFC3339))
	case "renew":
		if len(rest) != 0 {
			return errors.New("renew takes no arguments")
		}
		token, err := client.Renew(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("renewed %s until %s\n", token.TargetEmail, token.ExpiresAt.Local().Format(time.RFC3339))
	case "status":
		if len(rest) != 0 {
			return errors.New("status takes no arguments")
		}
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		return printJSON(status)
	case "token":
		fs := flag.NewFlagSet("token", flag.ContinueOnError)
		printToken := fs.Bool("print", false, "print the access token to stdout")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("token takes no positional arguments")
		}
		token, err := client.Token(ctx)
		if err != nil {
			return err
		}
		if *printToken {
			fmt.Println(token.AccessToken)
		} else {
			fmt.Printf("token for %s expires at %s (use --print to reveal it)\n", token.TargetEmail, token.ExpiresAt.Local().Format(time.RFC3339))
		}
	default:
		usage(global)
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

func serve(configPath, socket string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := pivsigner.CheckPCSC(); err != nil {
		return err
	}
	signer := &pivsigner.Hardware{Serials: cfg.YubiKeySerials, Notify: cfg.NotifyCmd, Logger: logger}
	minter := &gcp.Minter{Signer: signer, BrokerSA: cfg.BrokerSA, KeyID: cfg.KeyID, Logger: logger}
	agentCore := core.New(cfg, signer, minter, version.Value)
	api := &agentapi.API{Core: agentCore}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	errCh := make(chan error, 2)
	go func() {
		errCh <- agentapi.ServeUnix(ctx, socket, api.Handler(true))
	}()

	frontend := &metadata.Frontend{Agent: agentapi.NewClient(socket), Notify: cfg.NotifyCmd, Logger: logger}
	metadataServer := &http.Server{
		Addr: cfg.ListenMetadata, Handler: frontend.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Info("pivb serving", "agent_socket", socket, "metadata", cfg.ListenMetadata)
		err := metadataServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			cancel(err)
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = metadataServer.Shutdown(shutdownCtx)
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return nil
}

func metadataCommand(defaultAgent string, args []string) error {
	fs := flag.NewFlagSet("metadata", flag.ContinueOnError)
	agent := fs.String("agent", defaultAgent, "forwarded agent Unix socket")
	listen := fs.String("listen", "127.0.0.1:8642", "metadata listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("metadata takes no positional arguments")
	}
	if *agent == "" {
		return errors.New("XDG_RUNTIME_DIR is not set; pass metadata --agent explicitly")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{
		Addr: *listen, Handler: (&metadata.Frontend{Agent: agentapi.NewClient(*agent)}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func agentSocketPath() string {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		return ""
	}
	return filepath.Join(runtimeDir, "pivb", "agent.sock")
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

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func usage(fs *flag.FlagSet) {
	fmt.Fprintf(fs.Output(), "usage: pivb [--config path] [--agent socket] <command>\n\n")
	fmt.Fprintln(fs.Output(), "commands: serve, unlock, lock, use <alias>, renew, status, token [--print], metadata, version")
}
