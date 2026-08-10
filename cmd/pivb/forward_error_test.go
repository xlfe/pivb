package main

import (
	"errors"
	"net/http"
	"testing"

	"github.com/xlfe/pivb/internal/tokenapi"
)

func TestForwardContentionUsesSharedHardwareClassifier(t *testing.T) {
	mapped := mapForwardError(errors.New("open smart card: SCARD_E_SHARING_VIOLATION 0x8010000b"))
	if mapped.Status != http.StatusServiceUnavailable || mapped.Code != tokenapi.CodeSign {
		t.Fatalf("mapped = %+v, want 503/%s", mapped, tokenapi.CodeSign)
	}
}
