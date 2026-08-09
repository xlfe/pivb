// Package cardlease implements the cooperative smart-card lease owned by
// zkad. The networkless PIVB daemon holds the Unix connection for the exact
// duration of a hardware operation; closing it releases the lease.
package cardlease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const protocolVersion = 1

type Client struct{ Socket string }

const dialRetryBudget = 2 * time.Second

// UnavailableError identifies absence of the ZKA lease service. PIVB may
// bypass only this error for direct-local operations; protocol errors and an
// explicit lease denial always fail closed.
type UnavailableError struct{ Err error }

func (e *UnavailableError) Error() string {
	return "connect to zkad smart-card lease: " + e.Err.Error()
}
func (e *UnavailableError) Unwrap() error          { return e.Err }
func (e *UnavailableError) LeaseUnavailable() bool { return true }

type request struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
}

type response struct {
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

func (c Client) Acquire(ctx context.Context, operation string) (func(), error) {
	if c.Socket == "" || operation == "" {
		return nil, errors.New("smart-card lease socket and operation are required")
	}
	conn, err := dialLease(ctx, c.Socket)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	if err := json.NewEncoder(conn).Encode(request{Version: protocolVersion, Operation: operation}); err != nil {
		stop()
		_ = conn.Close()
		return nil, err
	}
	var reply response
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		stop()
		_ = conn.Close()
		return nil, fmt.Errorf("read zkad smart-card lease response: %w", err)
	}
	if reply.Version != protocolVersion || !reply.OK {
		stop()
		_ = conn.Close()
		if reply.Error == "" {
			reply.Error = "incompatible smart-card lease response"
		}
		return nil, errors.New(reply.Error)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			stop()
			_ = conn.Close()
		})
	}, nil
}

func dialLease(ctx context.Context, socket string) (net.Conn, error) {
	deadline := time.Now().Add(dialRetryBudget)
	var lastErr error
	for {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, &UnavailableError{Err: lastErr}
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
