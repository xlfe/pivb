package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/forwardapi"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/tokenapi"
)

type forwardBackend struct {
	core   *core.Core
	logger *slog.Logger
}

func (b forwardBackend) Policy(context.Context) (forwardapi.Policy, *tokenapi.APIError) {
	return b.core.ForwardPolicy(), nil
}

func (b forwardBackend) Describe(ctx context.Context) (forwardapi.Description, *tokenapi.APIError) {
	result, err := b.core.DescribeForwardProvider(ctx)
	if err != nil {
		return forwardapi.Description{}, mapForwardError(err)
	}
	return result, nil
}

func (b forwardBackend) Mint(ctx context.Context, req forwardapi.MintRequest) (forwardapi.MintResponse, *tokenapi.APIError) {
	if req.RequestSource == nil || req.ExpectedCard.Serial == 0 || req.ExpectedCard.KeyID == "" || len(req.ExpectedCard.SPKIDER) == 0 {
		return forwardapi.MintResponse{}, &tokenapi.APIError{Status: http.StatusBadRequest, Code: tokenapi.CodeConfig, Message: "forwarded PIVB request lacks source or claimed card identity", Remedy: "release and re-claim the PIVB credential bundle"}
	}
	fc := req.ForwardContext
	if !validForwardID(fc.OriginNodeID) || !validForwardID(fc.WorkspaceID) || !validForwardName(fc.Bundle) ||
		fc.ClaimGeneration == 0 || !validForwardID(fc.ProviderNodeID) || !validForwardID(fc.OperationID) ||
		fc.ProviderAttachID != "" && !validForwardID(fc.ProviderAttachID) {
		return forwardapi.MintResponse{}, &tokenapi.APIError{Status: http.StatusBadRequest, Code: tokenapi.CodeConfig, Message: "forwarded PIVB request lacks authenticated ZKA context", Remedy: "upgrade and re-claim the PIVB credential bundle"}
	}
	result, err := b.core.SubjectToken(ctx, core.SubjectTokenRequest{
		Alias: req.Alias, ExternalAccountAudience: req.ExternalAccountAudience,
		ImpersonatedEmail: req.ImpersonatedEmail, RequestSource: *req.RequestSource,
		ExpectedCard: req.ExpectedCard, ForwardContext: req.ForwardContext,
	})
	if err != nil {
		return forwardapi.MintResponse{}, mapForwardError(err)
	}
	b.logger.Info("minted forwarded WIF subject token",
		"alias", req.Alias, "target", req.ImpersonatedEmail,
		"source_label", req.RequestSource.Label, "session_id", req.RequestSource.SessionID,
		"origin_node", fc.OriginNodeID, "workspace", fc.WorkspaceID, "bundle", fc.Bundle,
		"claim_generation", fc.ClaimGeneration, "operation_id", fc.OperationID,
		"serial", result.Serial, "key_id", result.KeyID)
	return forwardapi.MintResponse{
		Version: forwardapi.ProtocolVersion, IDToken: result.IDToken, ExpirationTime: result.ExpiresAt.Unix(),
		Card:           forwardapi.CardIdentity{Serial: result.Serial, KeyID: result.KeyID, SPKIDER: result.SPKIDER},
		ExpectedCard:   req.ExpectedCard,
		ForwardContext: req.ForwardContext,
	}, nil
}

func validForwardID(value string) bool {
	if len(value) != 32 {
		return false
	}
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

func mapForwardError(err error) *tokenapi.APIError {
	var existing *tokenapi.APIError
	var unknownAlias *core.UnknownAliasError
	var mismatch *core.RequestMismatchError
	var invalidSource *core.RequestSourceError
	var pinErr *pivsigner.PINError
	switch {
	case errors.As(err, &existing):
		return existing
	case errors.Is(err, core.ErrLocked):
		return &tokenapi.APIError{Status: http.StatusConflict, Code: tokenapi.CodeLocked, Message: err.Error(), Remedy: "run `pivb unlock` on the YubiKey provider host"}
	case errors.As(err, &invalidSource), errors.As(err, &unknownAlias), errors.As(err, &mismatch):
		return &tokenapi.APIError{Status: http.StatusForbidden, Code: tokenapi.CodeConfig, Message: err.Error(), Remedy: "check the PIVB bundle and provider configuration"}
	case errors.As(err, &pinErr):
		remedy := pinErr.Remedy
		if remedy == "" {
			remedy = "run `pivb unlock` on the YubiKey provider host"
		}
		return &tokenapi.APIError{Status: http.StatusConflict, Code: tokenapi.CodePIN, Message: err.Error(), Remedy: remedy}
	default:
		return &tokenapi.APIError{Status: http.StatusBadGateway, Code: tokenapi.CodeSign, Message: fmt.Sprintf("PIVB provider failed: %v", err), Remedy: "check the provider card, touch prompt, and daemon journal"}
	}
}
