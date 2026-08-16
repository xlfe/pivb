package core

import (
	"fmt"
	"time"

	"github.com/xlfe/pivb/internal/forwardapi"
)

// This file holds one decision: what authorisation window this provider grants
// a forwarded mint. A window is an operator-granted touch-free period attached
// to a ZKA workspace claim — the origin stamps what the claim asked for, and
// the card's own operator decides how much of it to honour.
//
// The grant is a pure function of the request and this daemon's configuration.
// Nothing about it is remembered between mints: the claim carries its own
// anchor, so the same claim generation recomputes the same grant on every
// request, and a re-grant arrives as a new claim generation.

// WindowNotAllowedRemedy is what an operator does about a refused window. It
// lives with the error rather than in either error mapper, so both the
// forwarding socket and the local WIF socket tell them the same thing.
const WindowNotAllowedRemedy = "raise max_grant_window_s in the provider pivb configuration or re-claim without a window"

// WindowNotAllowedError refuses a mint that asked to be covered by an
// authorisation window on a provider whose operator grants none.
type WindowNotAllowedError struct{ Requested int64 }

func (e *WindowNotAllowedError) Error() string {
	return fmt.Sprintf("the mint asked to be covered by a %d-second authorisation window but this provider's max_grant_window_s is 0", e.Requested)
}

// grantedWindow decides the window this provider grants one forwarded mint. It
// returns the granted seconds and the absolute instant the grant ends, or a
// zero pair when no window applies at all.
//
// The claim anchored its window at the deadline it sent minus the seconds it
// asked for, so a grant shorter than the request ends earlier from that same
// start rather than later from now: a claim cannot lengthen its own window by
// re-asking near its end.
func (c *Core) grantedWindow(fc forwardapi.ForwardContext, now time.Time) (int64, time.Time, error) {
	if fc.WindowSeconds <= 0 {
		return 0, time.Time{}, nil
	}
	maximum := int64(c.cfg.MaxGrantWindowS)
	if maximum <= 0 {
		return 0, time.Time{}, &WindowNotAllowedError{Requested: fc.WindowSeconds}
	}
	granted := min(fc.WindowSeconds, maximum)
	claimStart := time.Unix(fc.WindowDeadline-fc.WindowSeconds, 0).UTC()
	deadline := claimStart.Add(time.Duration(granted) * time.Second)
	if !deadline.After(now) {
		// A window that has already ended is not a refusal. The claim reverts to
		// a touch per mint, which is exactly what a mint carrying no window is,
		// so this request is treated as carrying none.
		return 0, time.Time{}, nil
	}
	return granted, deadline, nil
}

// unixOrZero renders a granted deadline for the wire, keeping "no window" a
// zero rather than the unix epoch.
func unixOrZero(deadline time.Time) int64 {
	if deadline.IsZero() {
		return 0
	}
	return deadline.Unix()
}
