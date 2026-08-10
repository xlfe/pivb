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

type Client struct {
	Socket string
	dial   func(context.Context, string, string) (net.Conn, error)
}

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

func (c Client) Acquire(ctx context.Context, operation string, acquireBudget time.Duration) (func(), error) {
	if c.Socket == "" || operation == "" {
		return nil, errors.New("smart-card lease socket and operation are required")
	}
	if acquireBudget <= 0 || acquireBudget > dialRetryBudget {
		acquireBudget = dialRetryBudget
	}
	started := time.Now()
	exchangeDeadline := started.Add(acquireBudget)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(exchangeDeadline) {
		exchangeDeadline = callerDeadline
	}
	available := time.Until(exchangeDeadline)
	if available <= 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, context.DeadlineExceeded
	}
	// Reserve the final quarter (at most 250ms) for the JSON exchange. A
	// successful connect at the end of its retry window must not inherit an
	// already-expired deadline.
	exchangeReserve := available / 4
	if exchangeReserve > 250*time.Millisecond {
		exchangeReserve = 250 * time.Millisecond
	}
	dialBudget := available - exchangeReserve
	conn, err := dialLease(ctx, c.Socket, dialBudget, c.dial)
	if err != nil {
		return nil, err
	}
	// Bound the protocol exchange as well as connect(2). The accepted lease
	// itself remains tied to the caller context below; an internal dial
	// context must never become the lease-lifetime context.
	if err := conn.SetDeadline(exchangeDeadline); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("bound zkad smart-card lease exchange: %w", err)
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
	if err := conn.SetDeadline(time.Time{}); err != nil {
		stop()
		_ = conn.Close()
		return nil, fmt.Errorf("clear zkad smart-card lease deadline: %w", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			stop()
			_ = conn.Close()
		})
	}, nil
}

func dialLease(ctx context.Context, socket string, budget time.Duration, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	deadline := time.Now().Add(budget)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr == nil {
				lastErr = context.DeadlineExceeded
			}
			return nil, &UnavailableError{Err: lastErr}
		}
		attemptCtx, cancel := context.WithDeadline(ctx, deadline)
		if dial == nil {
			dialer := &net.Dialer{Timeout: remaining}
			dial = dialer.DialContext
		}
		conn, err := dial(attemptCtx, "unix", socket)
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !time.Now().Before(deadline) {
			return nil, &UnavailableError{Err: lastErr}
		}
		wait := 100 * time.Millisecond
		if remaining = time.Until(deadline); wait > remaining {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
