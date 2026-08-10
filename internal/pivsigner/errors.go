package pivsigner

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/xlfe/pivb/internal/tokenapi"
)

// TouchWindowError avoids prompting after contention has consumed so much of
// the hardware deadline that the attempt's minimum useful touch window cannot
// fit.
type TouchWindowError struct{ Remaining time.Duration }

func (e *TouchWindowError) Error() string {
	return fmt.Sprintf("smart-card contention left only %s for a touch-gated signature", e.Remaining.Round(time.Millisecond))
}

// MapAPIError is the single hardware-error classifier used by the control,
// local WIF, and forwarded-provider adapters.
func MapAPIError(err error) (*tokenapi.APIError, bool) {
	var contention *ContentionError
	if errors.As(err, &contention) {
		remedy := "close the competing smart-card client and retry"
		switch {
		case contention.LastSelfHeld:
			remedy = "wait for the earlier PIVB touch/signing operation to finish, then retry"
		case contention.CooldownRemaining > 0:
			remedy = fmt.Sprintf("retry in %s; repeated automated scdaemon hand-offs are temporarily limited", displayDelay(contention.CooldownRemaining))
		case contention.SCDRunning == scdaemonStopped:
			remedy = "another non-scdaemon client owns the card; close it and retry"
		case contention.HandoffError != nil:
			remedy = "check the GnuPG command path/home and the competing card client, then retry"
		case contention.InspectionError != nil:
			remedy = "scdaemon state could not be inspected; check the GnuPG command path/home and competing card client, then retry"
		}
		return &tokenapi.APIError{Status: http.StatusServiceUnavailable, Code: tokenapi.CodeSign, Message: err.Error(), Remedy: remedy}, true
	}
	var touchWindow *TouchWindowError
	if errors.As(err, &touchWindow) {
		return &tokenapi.APIError{
			Status: http.StatusServiceUnavailable, Code: tokenapi.CodeSign, Message: err.Error(),
			Remedy: "the card was contended too long to prompt for touch safely; retry",
		}, true
	}
	if IsSharingViolation(err) {
		return &tokenapi.APIError{
			Status: http.StatusServiceUnavailable, Code: tokenapi.CodeSign, Message: err.Error(),
			Remedy: "close the competing smart-card client, check the daemon journal, and retry",
		}, true
	}
	return nil, false
}

func displayDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	return ((delay + time.Second - 1) / time.Second) * time.Second
}
