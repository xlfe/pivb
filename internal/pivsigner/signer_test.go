package pivsigner

import (
	"context"
	"errors"
	"fmt"
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
