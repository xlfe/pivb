package pivsigner

import (
	"errors"
	"fmt"
	"testing"
)

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
