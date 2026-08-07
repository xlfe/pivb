// Package jsonhttp provides the closed-shape JSON request and response
// primitives shared by PIVB's Unix-socket HTTP APIs.
package jsonhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Decode reads exactly one size-bounded JSON document and rejects unknown
// fields. Callers retain ownership of the wire type and error response.
func Decode(r *http.Request, dst any, maxBytes int64) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid JSON body: multiple values")
	}
	return nil
}

// Write writes one JSON response document.
func Write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
