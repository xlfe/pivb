package cardlease

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireHoldsConnectionUntilRelease(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "lease.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	held := make(chan request, 1)
	released := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var req request
		if json.NewDecoder(conn).Decode(&req) != nil {
			return
		}
		held <- req
		if json.NewEncoder(conn).Encode(response{Version: protocolVersion, OK: true}) != nil {
			return
		}
		var one [1]byte
		_, _ = conn.Read(one[:])
		close(released)
	}()

	release, err := (Client{Socket: socket}).Acquire(context.Background(), "pivb-mint", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if req := <-held; req.Version != protocolVersion || req.Operation != "pivb-mint" {
		t.Fatalf("lease request = %#v", req)
	}
	select {
	case <-released:
		t.Fatal("lease connection closed before release")
	default:
	}
	release()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("lease connection remained open after release")
	}
}

func TestAcquireBoundsUnresponsiveLeaseProtocol(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "lease.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	started := time.Now()
	_, err = (Client{Socket: socket}).Acquire(context.Background(), "pivb-mint", 75*time.Millisecond)
	if err == nil {
		t.Fatal("Acquire succeeded without a lease response")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("Acquire took %s, want a hard protocol bound", elapsed)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	default:
	}
}

func TestAcquireAttemptContextDoesNotOwnAcceptedLease(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "lease.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	released := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var req request
		_ = json.NewDecoder(conn).Decode(&req)
		_ = json.NewEncoder(conn).Encode(response{Version: protocolVersion, OK: true})
		var b [1]byte
		_, _ = conn.Read(b[:])
		close(released)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	release, err := (Client{Socket: socket}).Acquire(ctx, "pivb-mint", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	// The internal per-attempt context has already been canceled. The lease
	// must still be held by the original caller context.
	select {
	case <-released:
		t.Fatal("per-attempt cancellation closed the held lease")
	case <-time.After(25 * time.Millisecond):
	}
	cancel()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not close the held lease")
	}
	release()
}

func TestAcquireBoundsBlockedDialAttempt(t *testing.T) {
	client := Client{
		Socket: "/not-used-by-injected-dial",
		dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	started := time.Now()
	_, err := client.Acquire(context.Background(), "pivb-mint", 50*time.Millisecond)
	if err == nil {
		t.Fatal("blocked dial unexpectedly acquired a lease")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("blocked dial took %s, want per-attempt context/timeout bound", elapsed)
	}
}

func TestAcquireReservesTimeForExchangeAfterSlowDial(t *testing.T) {
	client := Client{
		Socket: "/not-used-by-injected-dial",
		dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				return nil, errors.New("dial attempt has no deadline")
			}
			delay := time.Until(deadline) - 20*time.Millisecond
			if delay < 0 {
				delay = 0
			}
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				var req request
				if json.NewDecoder(serverConn).Decode(&req) != nil {
					return
				}
				time.Sleep(30 * time.Millisecond)
				_ = json.NewEncoder(serverConn).Encode(response{Version: protocolVersion, OK: true})
				var one [1]byte
				_, _ = serverConn.Read(one[:])
			}()
			return clientConn, nil
		},
	}
	release, err := client.Acquire(context.Background(), "pivb-mint", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("exchange lost its reserved allowance after slow dial: %v", err)
	}
	release()
}

func TestAcquireDoesNotReclassifyCallerCancellationAsUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := Client{Socket: "/not-used"}
	_, err := client.Acquire(ctx, "pivb-mint", time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %T %v, want caller cancellation", err, err)
	}
	var unavailable *UnavailableError
	if errors.As(err, &unavailable) {
		t.Fatal("caller cancellation was reclassified as an optional lease outage")
	}
}
