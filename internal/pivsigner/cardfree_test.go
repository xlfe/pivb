package pivsigner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/tokenapi"
)

func TestCardFreeSignerRefusesByType(t *testing.T) {
	var signer Signer = CardFree{}

	var cardFree *CardFreeError
	if _, _, err := signer.VerifyPIN(context.Background(), "123456"); !errors.As(err, &cardFree) {
		t.Fatalf("VerifyPIN error = %v, want *CardFreeError", err)
	}
	if _, _, err := signer.Sign(context.Background(), "label", "123456", nil); !errors.As(err, &cardFree) {
		t.Fatalf("Sign error = %v, want *CardFreeError", err)
	}
	if !strings.Contains(cardFree.Error(), `card = "none"`) {
		t.Errorf("refusal does not name the configuration: %v", cardFree)
	}

	// Absence is part of the contract: no Describer means provider discovery
	// refuses in core, and no reader lister means the reuse notifier's card
	// presence probe stays disabled instead of failing.
	if _, ok := signer.(Describer); ok {
		t.Error("CardFree implements Describer; a card-free origin must not describe a live card")
	}
	if _, ok := signer.(interface{ ListReaderNames() ([]string, error) }); ok {
		t.Error("CardFree implements ListReaderNames; the presence probe must stay disabled, not fail")
	}
}

func TestMapAPIErrorClassifiesCardFree(t *testing.T) {
	mapped, ok := MapAPIError(fmt.Errorf("wrapped: %w", &CardFreeError{Operation: "verify a PIV PIN"}))
	if !ok {
		t.Fatal("MapAPIError did not classify a CardFreeError")
	}
	if mapped.Status != http.StatusForbidden || mapped.Code != tokenapi.CodeCardFree {
		t.Fatalf("mapped = %d/%s, want 403/%s", mapped.Status, mapped.Code, tokenapi.CodeCardFree)
	}
	if mapped.Remedy != CardFreeRemedy {
		t.Errorf("default remedy = %q, want CardFreeRemedy", mapped.Remedy)
	}

	specific, ok := MapAPIError(&CardFreeError{Operation: "describe a live provider card", Remedy: "create the bundle on the provider host"})
	if !ok || specific.Remedy != "create the bundle on the provider host" {
		t.Fatalf("specific remedy was not preserved: %#v", specific)
	}
}
