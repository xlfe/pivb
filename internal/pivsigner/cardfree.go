package pivsigner

import (
	"context"
	"crypto/x509"
	"fmt"
)

// CardFreeRemedy is what an operator does about a card operation reaching a
// card-free origin. It lives here so every socket adapter tells them the same
// thing through MapAPIError.
const CardFreeRemedy = "perform card operations on the provider host that holds the YubiKey; this origin serves only routed mints, policy, and status"

// CardFreeError refuses an operation that needs the local YubiKey on a daemon
// configured card = "none". It names the configuration rather than a hardware
// fault: nothing is broken, the card is somewhere else.
type CardFreeError struct {
	// Operation is the refused card operation, phrased as an infinitive
	// ("verify a PIV PIN"), and Remedy overrides CardFreeRemedy where a more
	// specific instruction exists.
	Operation string
	Remedy    string
}

func (e *CardFreeError) Error() string {
	return fmt.Sprintf("cannot %s: this pivb daemon is configured card = \"none\" (card-free ZKA origin) and opens no smart-card connection", e.Operation)
}

// CardFree is the signer a card-free origin serves with. Every method returns
// a CardFreeError, so a card operation that slips past the configuration
// guards in core still fails closed with the right code instead of reaching
// for hardware that is not there. It deliberately implements neither Describer
// nor the notifier's reader-lister seam: provider discovery and the reuse
// presence probe are card-host behaviour.
type CardFree struct{}

func (CardFree) VerifyPIN(context.Context, string) (uint32, int, error) {
	return 0, -1, &CardFreeError{Operation: "verify a PIV PIN"}
}

func (CardFree) Sign(context.Context, string, string, func(uint32, *x509.Certificate) ([]byte, error)) ([]byte, uint32, error) {
	return nil, 0, &CardFreeError{Operation: "sign with the local PIV key"}
}
