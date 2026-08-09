package cardlease

import (
	"context"
	"encoding/json"
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

	release, err := (Client{Socket: socket}).Acquire(context.Background(), "pivb-mint")
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
