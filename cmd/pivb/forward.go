package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/forwardapi"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/uds"
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
	if !validForwardContext(fc) {
		return forwardapi.MintResponse{}, &tokenapi.APIError{Status: http.StatusBadRequest, Code: tokenapi.CodeConfig, Message: "forwarded PIVB request lacks authenticated ZKA context", Remedy: "upgrade and re-claim the PIVB credential bundle"}
	}
	// Protocol 3 carries authorisation windows, but no provider enforces one
	// yet. Until the enforcement work package lands, a mint that asks to be
	// covered by a window is refused rather than served without the coverage
	// it asked for.
	if fc.WindowSeconds > 0 {
		return forwardapi.MintResponse{}, &tokenapi.APIError{
			Status: http.StatusForbidden, Code: tokenapi.CodeWindowNotAllowed,
			Message: "a grant window was requested but this provider does not allow windows",
			Remedy:  "enable grant windows in the provider pivb configuration or re-claim without a window",
		}
	}
	result, err := b.core.SubjectToken(ctx, core.SubjectTokenRequest{
		Alias: req.Alias, ExternalAccountAudience: req.ExternalAccountAudience,
		ImpersonatedEmail: req.ImpersonatedEmail, RequestSource: *req.RequestSource,
		Attachment:   attachment.LocalAllowed(),
		ExpectedCard: req.ExpectedCard, ForwardContext: req.ForwardContext,
	})
	if err != nil {
		return forwardapi.MintResponse{}, mapForwardError(err)
	}
	attrs := []any{
		"alias", req.Alias, "target", req.ImpersonatedEmail,
		"source_label", req.RequestSource.Label, "session_id", req.RequestSource.SessionID,
		"origin_node", fc.OriginNodeID, "workspace", fc.WorkspaceID, "bundle", fc.Bundle,
		"claim_generation", fc.ClaimGeneration, "provider_attachment_id", fc.ProviderAttachID,
		"operation_id", fc.OperationID,
		"serial", result.Serial, "key_id", result.KeyID,
	}
	// The peer on this socket is the local zka daemon relaying the request,
	// not the agent that started it; the ZKA context above names that.
	if peer, ok := uds.PeerFromContext(ctx); ok {
		attrs = append(attrs, "peer_pid", peer.PID)
	}
	b.logger.Info("minted forwarded WIF subject token", attrs...)
	return forwardapi.MintResponse{
		Version: forwardapi.ProtocolVersion, IDToken: result.IDToken, ExpirationTime: result.ExpiresAt.Unix(),
		Card:           forwardapi.CardIdentity{Serial: result.Serial, KeyID: result.KeyID, SPKIDER: result.SPKIDER},
		ExpectedCard:   req.ExpectedCard,
		ForwardContext: req.ForwardContext,
	}, nil
}

// Invalidate drops the assertions held for one workspace claim. ZKA calls it
// when a claim is released or its generation advances, so a released claim
// stops granting touch-free mints at once instead of when its assertions
// expire. Unlike a mint, generation zero is meaningful here: it is the release
// case, "every generation of this workspace".
func (b forwardBackend) Invalidate(ctx context.Context, req forwardapi.InvalidateRequest) (forwardapi.InvalidateResponse, *tokenapi.APIError) {
	if !validForwardID(req.WorkspaceID) {
		return forwardapi.InvalidateResponse{}, &tokenapi.APIError{Status: http.StatusBadRequest, Code: tokenapi.CodeConfig, Message: "forwarded PIVB invalidation lacks an authenticated ZKA workspace", Remedy: "upgrade and re-claim the PIVB credential bundle"}
	}
	purged := b.core.InvalidateWorkspace(req.WorkspaceID, req.ClaimGeneration)
	attrs := []any{"workspace", req.WorkspaceID, "claim_generation", req.ClaimGeneration, "purged", purged}
	if peer, ok := uds.PeerFromContext(ctx); ok {
		attrs = append(attrs, "peer_pid", peer.PID)
	}
	b.logger.Info("invalidated forwarded PIVB assertions", attrs...)
	return forwardapi.InvalidateResponse{Version: forwardapi.ProtocolVersion, Purged: purged}, nil
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
		if hardwareErr, ok := pivsigner.MapAPIError(err); ok {
			return hardwareErr
		}
		return &tokenapi.APIError{Status: http.StatusBadGateway, Code: tokenapi.CodeSign, Message: fmt.Sprintf("PIVB provider failed: %v", err), Remedy: "check the provider card, touch prompt, and daemon journal"}
	}
}
