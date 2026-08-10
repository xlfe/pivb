//go:build hardware

package pivsigner

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// This opt-in test constructs Hardware directly with a short deadline; it
// intentionally does not add a production deadline setting merely to test
// the touch-reservation branch.
func TestHardwareShortDeadlineNeverPromptsForTouch(t *testing.T) {
	serialText := os.Getenv("PIVB_HARDWARE_SERIAL")
	pin := os.Getenv("PIVB_HARDWARE_PIN")
	if serialText == "" || pin == "" {
		t.Skip("set PIVB_HARDWARE_SERIAL and PIVB_HARDWARE_PIN")
	}
	serial64, err := strconv.ParseUint(serialText, 10, 32)
	if err != nil || serial64 == 0 {
		t.Fatalf("PIVB_HARDWARE_SERIAL: %v", err)
	}
	var notified atomic.Bool
	h := &Hardware{Serials: []uint32{uint32(serial64)}, Deadline: 15 * time.Second, notifyFunc: func(string) { notified.Store(true) }}
	_, _, err = h.Sign(context.Background(), "hardware short-deadline acceptance", pin, func(uint32, *x509.Certificate) ([]byte, error) {
		digest, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		return digest, nil
	})
	var touchWindow *TouchWindowError
	if !errors.As(err, &touchWindow) {
		t.Fatalf("error = %T %v, want TouchWindowError", err, err)
	}
	if notified.Load() {
		t.Fatal("short deadline emitted a touch notification")
	}
}
