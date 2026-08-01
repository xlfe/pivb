package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/xlfe/pivb/internal/core"
)

var errPinentryCancelled = errors.New("pinentry cancelled")

type unlockAgent interface {
	Status(context.Context) (core.Status, error)
	Unlock(context.Context, string) (int, error)
}

func unlockCommand(ctx context.Context, client unlockAgent, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	ifNeeded := fs.Bool("if-needed", false, "return without prompting when the PIN is already cached")
	pinentryProgram := fs.String("pinentry-program", "", "read the PIN from this pinentry executable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unlock takes no positional arguments")
	}
	if *ifNeeded {
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		if status.PINCached {
			_, err := fmt.Fprintln(out, "already unlocked")
			return err
		}
	}

	var (
		pin []byte
		err error
	)
	if *pinentryProgram == "" {
		pin, err = readPIN()
	} else {
		pin, err = readPINFromPinentry(ctx, *pinentryProgram)
	}
	if err != nil {
		return err
	}
	defer zero(pin)
	retries, err := client.Unlock(ctx, string(pin))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "unlocked (PIN retries available: %d)\n", retries)
	return err
}

func readPINFromPinentry(ctx context.Context, program string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, program)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open pinentry stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open pinentry stdout: %w", err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start pinentry: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	writer := bufio.NewWriter(stdin)
	finished := false
	finish := func() error {
		if finished {
			return nil
		}
		finished = true
		_, _ = fmt.Fprintln(writer, "BYE")
		_ = writer.Flush()
		_ = stdin.Close()
		return cmd.Wait()
	}
	defer func() { _ = finish() }()

	if _, err := readAssuanReply(scanner); err != nil {
		return nil, fmt.Errorf("start pinentry protocol: %w", err)
	}
	for _, request := range []string{
		"SETTITLE " + assuanEscape("pivb credential unlock"),
		"SETDESC " + assuanEscape("Unlock pivb. Only enter your PIN after requesting this action."),
		"SETPROMPT " + assuanEscape("YubiKey PIV PIN:"),
	} {
		if err := writeAssuanRequest(writer, request); err != nil {
			return nil, err
		}
		if _, err := readAssuanReply(scanner); err != nil {
			return nil, err
		}
	}
	if err := writeAssuanRequest(writer, "GETPIN"); err != nil {
		return nil, err
	}
	pin, err := readAssuanReply(scanner)
	if err != nil {
		return nil, err
	}
	if len(pin) == 0 {
		return nil, errors.New("pinentry returned an empty PIN")
	}
	if err := finish(); err != nil {
		zero(pin)
		return nil, fmt.Errorf("wait for pinentry: %w", err)
	}
	return pin, nil
}

func writeAssuanRequest(writer *bufio.Writer, request string) error {
	if _, err := fmt.Fprintln(writer, request); err != nil {
		return fmt.Errorf("write pinentry request: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush pinentry request: %w", err)
	}
	return nil
}

func readAssuanReply(scanner *bufio.Scanner) ([]byte, error) {
	var data []byte
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "OK" || strings.HasPrefix(line, "OK "):
			return data, nil
		case strings.HasPrefix(line, "D "):
			decoded, err := url.PathUnescape(strings.TrimPrefix(line, "D "))
			if err != nil {
				zero(data)
				return nil, errors.New("pinentry returned invalid escaped data")
			}
			data = append(data, decoded...)
		case strings.HasPrefix(line, "ERR "):
			zero(data)
			if strings.HasPrefix(line, "ERR 83886179 ") ||
				strings.HasPrefix(line, "ERR 83886180 ") ||
				strings.Contains(strings.ToLower(line), "cancel") {
				return nil, errPinentryCancelled
			}
			return nil, fmt.Errorf("pinentry error: %s", line)
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "S "):
			continue
		default:
			zero(data)
			return nil, errors.New("unexpected pinentry protocol response")
		}
	}
	zero(data)
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read pinentry response: %w", err)
	}
	return nil, io.ErrUnexpectedEOF
}

func assuanEscape(value string) string {
	replacer := strings.NewReplacer("%", "%25", "\n", "%0A", "\r", "%0D")
	return replacer.Replace(value)
}
