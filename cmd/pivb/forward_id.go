package main

import "github.com/xlfe/pivb/internal/forwardapi"

func validForwardContext(fc forwardapi.ForwardContext) bool {
	return validForwardID(fc.OriginNodeID) && validForwardID(fc.WorkspaceID) && validForwardName(fc.Bundle) &&
		fc.ClaimGeneration != 0 && validForwardID(fc.ProviderNodeID) && validForwardID(fc.OperationID) &&
		(fc.ProviderAttachID == "" || validForwardAttachmentID(fc.ProviderAttachID)) && validForwardWindow(fc)
}

// A mint either carries a whole authorisation window — a length and the
// absolute deadline the claim anchored it to — or carries no window at all.
// Half a window has no meaning a provider could enforce.
func validForwardWindow(fc forwardapi.ForwardContext) bool {
	if fc.WindowSeconds < 0 || fc.WindowDeadline < 0 {
		return false
	}
	return (fc.WindowSeconds == 0) == (fc.WindowDeadline == 0)
}

func validForwardID(value string) bool {
	return len(value) == 32 && validLowerHex(value)
}

// ZKA uses 24 hex characters for deterministic attachment IDs and 32 for
// random fallback attachment IDs.
func validForwardAttachmentID(value string) bool {
	return (len(value) == 24 || len(value) == 32) && validLowerHex(value)
}

func validLowerHex(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validForwardName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || i > 0 && (r == '.' || r == '_' || r == '-') {
			continue
		}
		return false
	}
	return true
}
