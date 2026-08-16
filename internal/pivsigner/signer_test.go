package pivsigner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeLeaseManager struct{ err error }

func (f fakeLeaseManager) Acquire(context.Context, string, time.Duration) (func(), error) {
	return func() {}, f.err
}

type unavailableLeaseError struct{}

func (unavailableLeaseError) Error() string          { return "zkad is restarting" }
func (unavailableLeaseError) LeaseUnavailable() bool { return true }

func TestSharingViolationClassifier(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"piv-go v2.6 linux text", errors.New("open smart card: the smart card cannot be accessed because of other connections outstanding"), true},
		{"raw pcsc code upper", errors.New("SCardConnect failed: 0x8010000B"), true},
		{"named error", errors.New("SCARD_E_SHARING_VIOLATION: sharing violation"), true},
		{"wrapped", fmt.Errorf("open: %w", errors.New("0x8010000b")), true},
		{"timeout", errors.New("the user-specified timeout value has expired"), false},
		{"no card", errors.New("no configured YubiKey present"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsSharingViolation(tc.err); got != tc.want {
				t.Fatalf("IsSharingViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestWorkspaceLeaseFailsClosedWhileDirectLocalMayContinue(t *testing.T) {
	hardware := &Hardware{Lease: fakeLeaseManager{err: unavailableLeaseError{}}}
	release, err := hardware.acquireLease(context.Background(), "pivb-mint", time.Second)
	if err != nil {
		t.Fatalf("direct-local lease outage: %v", err)
	}
	release()

	if _, err := hardware.acquireLease(RequireLease(context.Background()), "pivb-mint", time.Second); err == nil {
		t.Fatal("workspace-forwarded operation bypassed an unavailable lease")
	}
	hardware.Lease = fakeLeaseManager{err: errors.New("lease denied")}
	if _, err := hardware.acquireLease(context.Background(), "pivb-mint", time.Second); err == nil {
		t.Fatal("direct-local operation bypassed an explicit lease error")
	}
}

// TestListReaderNamesUsesTheReaderSeam keeps the card-presence probe on the
// same enumeration the card selector uses, so what core compares is what the
// signer would actually open.
func TestListReaderNamesUsesTheReaderSeam(t *testing.T) {
	want := []string{"Yubico YubiKey OTP+FIDO+CCID 00 00", "gpg"}
	hardware := &Hardware{listReaders: func() ([]string, error) { return want, nil }}
	got, err := hardware.ListReaderNames()
	if err != nil {
		t.Fatalf("ListReaderNames: %v", err)
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("ListReaderNames() = %q, want %q", got, want)
	}

	failing := &Hardware{listReaders: func() ([]string, error) { return nil, errors.New("pcscd is unavailable") }}
	if _, err := failing.ListReaderNames(); err == nil {
		t.Error("a failed enumeration was reported as an empty reader list")
	}
}

// TestNotifyCommandRunsTheConfiguredCommand pins the notifier both halves of
// the daemon share: the message is the final argument, an empty argv disables
// notifications, and a command that cannot start never fails its caller.
func TestNotifyCommandRunsTheConfiguredCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "notified")
	NotifyCommand([]string{"sh", "-c", `printf '%s' "$1" > ` + marker, "sh"}, nil)("touch YubiKey")
	deadline := time.Now().Add(5 * time.Second)
	for {
		body, err := os.ReadFile(marker)
		if err == nil {
			if string(body) != "touch YubiKey" {
				t.Fatalf("notifier delivered %q", body)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("notifier wrote nothing: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	NotifyCommand(nil, nil)("dropped")
	NotifyCommand([]string{"/nonexistent/pivb-notifier"}, slog.New(slog.NewTextHandler(io.Discard, nil)))("dropped")
}

// TestHardwareNotifyPrefersTheInjectedSeam keeps the test seam ahead of the
// configured command.
func TestHardwareNotifyPrefersTheInjectedSeam(t *testing.T) {
	var seen []string
	hardware := &Hardware{
		Notify:     []string{"/nonexistent/pivb-notifier"},
		notifyFunc: func(message string) { seen = append(seen, message) },
	}
	hardware.notify("Touch YubiKey to sign ro")
	if len(seen) != 1 || seen[0] != "Touch YubiKey to sign ro" {
		t.Fatalf("injected notifier saw %q", seen)
	}
}
