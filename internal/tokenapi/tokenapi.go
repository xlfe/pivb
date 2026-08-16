// Package tokenapi contains the credential-neutral wire types shared by the
// trusted-host WIF API and the fixed-alias agent-session relay. It deliberately
// has no dependency on configuration, the daemon core, or PIV hardware.
package tokenapi

import "fmt"

// Stable machine-readable error codes surfaced through executable credential
// sources.
const (
	CodeLocked        = "PIVB_LOCKED"
	CodeConfig        = "PIVB_CONFIG"
	CodePIN           = "PIVB_PIN"
	CodeSign          = "PIVB_SIGN"
	CodeUnavailable   = "PIVB_UNAVAILABLE"
	CodeRouteRequired = "PIVB_ROUTE_REQUIRED"
	CodeEnv           = "PIVB_ENV"
	CodeInternal      = "PIVB_INTERNAL"
	// CodeWindowNotAllowed answers a mint that asked to be covered by an
	// authorisation window this provider will not grant.
	CodeWindowNotAllowed = "PIVB_WINDOW_NOT_ALLOWED"
	// CodeCardFree answers an operation that needs the local YubiKey on a
	// daemon configured card = "none" — a card-free ZKA origin.
	CodeCardFree = "PIVB_CARD_FREE"
)

// SubjectTokenResponse carries the subject token and its Unix expiry. No
// other credential state exists to return.
type SubjectTokenResponse struct {
	IDToken        string `json:"id_token"`
	ExpirationTime int64  `json:"expiration_time"`
}

// ErrorResponse is the common structured rejection returned by both sockets.
type ErrorResponse struct {
	Error  string `json:"error"`
	Code   string `json:"code"`
	Remedy string `json:"remedy,omitempty"`
}

// APIError is a structured socket rejection with a stable code.
type APIError struct {
	Status           int
	Code             string
	Message          string
	Remedy           string
	SecurityRelevant bool
}

func (e *APIError) Error() string {
	if e.Remedy != "" {
		return fmt.Sprintf("pivb daemon %s: %s (remedy: %s)", e.Code, e.Message, e.Remedy)
	}
	return fmt.Sprintf("pivb daemon %s: %s", e.Code, e.Message)
}
