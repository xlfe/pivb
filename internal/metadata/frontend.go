package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/xlfe/pivb/internal/agentapi"
	"github.com/xlfe/pivb/internal/core"
)

const (
	prefix     = "/computeMetadata/v1/"
	cloudScope = "https://www.googleapis.com/auth/cloud-platform"
)

type Agent interface {
	Status(context.Context) (core.Status, error)
	Token(context.Context) (core.Token, error)
	Identity(context.Context, string) (core.Identity, error)
}

type serviceAccountInfo struct {
	Aliases []string `json:"aliases"`
	Email   string   `json:"email"`
	Scopes  []string `json:"scopes"`
}

type Frontend struct {
	Agent  Agent
	Notify []string
	Logger *slog.Logger
	Now    func() time.Time

	mu             sync.Mutex
	notifiedExpiry time.Time
}

func (f *Frontend) Handler() http.Handler {
	return http.HandlerFunc(f.serveHTTP)
}

func (f *Frontend) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Metadata-Flavor", "Google")
	if r.Method != http.MethodGet {
		f.error(w, http.StatusMethodNotAllowed, "metadata frontend only supports GET", "use a documented metadata endpoint")
		return
	}
	if r.URL.Path == "/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/computeMetadata/") {
		f.error(w, http.StatusNotFound, "unknown metadata path", "use /computeMetadata/v1/")
		return
	}
	if r.Header.Get("Metadata-Flavor") != "Google" {
		f.error(w, http.StatusForbidden, "Metadata-Flavor: Google request header is required", "set Metadata-Flavor: Google")
		return
	}
	if !strings.HasPrefix(r.URL.Path, prefix) {
		f.error(w, http.StatusNotFound, "unsupported metadata API version", "use /computeMetadata/v1/")
		return
	}
	status, err := f.Agent.Status(r.Context())
	if err != nil {
		f.agentError(w, err)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	switch {
	case path == "instance/service-accounts/":
		if recursiveRequested(r) {
			info := serviceAccountMetadata(status.TargetEmail)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]serviceAccountInfo{
				"default":          info,
				status.TargetEmail: info,
			})
			return
		}
		f.text(w, "default/\n"+status.TargetEmail+"/\n")
	case path == "project/project-id":
		f.text(w, status.ProjectID)
	case path == "project/numeric-project-id":
		if status.NumericProject == "" {
			f.error(w, http.StatusNotFound, "numeric_project_id is not configured for active alias "+status.ActiveAlias, "set aliases."+status.ActiveAlias+".numeric_project_id")
			return
		}
		f.text(w, status.NumericProject)
	case path == "universe/universe-domain":
		f.text(w, "googleapis.com")
	default:
		f.serviceAccount(w, r, status, path)
	}
}

func (f *Frontend) serviceAccount(w http.ResponseWriter, r *http.Request, status core.Status, path string) {
	base := "instance/service-accounts/"
	if !strings.HasPrefix(path, base) {
		f.error(w, http.StatusNotFound, "unknown metadata path", "use a documented metadata endpoint")
		return
	}
	rest := strings.TrimPrefix(path, base)
	var suffix string
	switch {
	case strings.HasPrefix(rest, "default/"):
		suffix = strings.TrimPrefix(rest, "default/")
	case strings.HasPrefix(rest, status.TargetEmail+"/"):
		suffix = strings.TrimPrefix(rest, status.TargetEmail+"/")
	default:
		f.error(w, http.StatusNotFound, "service account is not active", "use default or "+status.TargetEmail)
		return
	}
	switch suffix {
	case "":
		if recursiveRequested(r) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(serviceAccountMetadata(status.TargetEmail))
			return
		}
		f.text(w, "aliases\nemail\nidentity\nscopes\ntoken\n")
	case "email":
		f.text(w, status.TargetEmail)
	case "scopes":
		f.text(w, cloudScope+"\n")
	case "token":
		if scopes, present := r.URL.Query()["scopes"]; present {
			f.logger().Debug("metadata token scopes query parameter ignored", "requested_scopes", scopes, "served_scope", cloudScope)
		}
		token, err := f.Agent.Token(r.Context())
		if err != nil {
			f.agentError(w, err)
			return
		}
		remaining := int64(token.ExpiresAt.Sub(f.now()).Seconds())
		if remaining <= 0 {
			f.error(w, http.StatusServiceUnavailable, "cached token is expired", "run `pivb unlock` then `pivb renew`")
			return
		}
		if remaining < 240 {
			f.expiryNotification(status.ActiveAlias, token.ExpiresAt, remaining)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int64  `json:"expires_in"`
			TokenType   string `json:"token_type"`
		}{token.AccessToken, remaining, "Bearer"})
	case "identity":
		audience := r.URL.Query().Get("audience")
		if audience == "" {
			f.error(w, http.StatusBadRequest, "audience query parameter is required", "add ?audience=<intended-recipient>")
			return
		}
		id, err := f.Agent.Identity(r.Context(), audience)
		if err != nil {
			f.agentError(w, err)
			return
		}
		f.text(w, id.Token)
	case "aliases":
		f.text(w, "default\n")
	default:
		f.error(w, http.StatusNotFound, "unknown service-account metadata path", "use aliases, email, identity, scopes, or token")
	}
}

func recursiveRequested(r *http.Request) bool {
	return strings.EqualFold(r.URL.Query().Get("recursive"), "true")
}

func serviceAccountMetadata(email string) serviceAccountInfo {
	return serviceAccountInfo{
		Aliases: []string{"default"},
		Email:   email,
		Scopes:  []string{cloudScope},
	}
}

func (f *Frontend) agentError(w http.ResponseWriter, err error) {
	var httpErr *agentapi.HTTPError
	if errors.As(err, &httpErr) {
		status := httpErr.Status
		if status >= 500 {
			status = http.StatusServiceUnavailable
		}
		f.error(w, status, httpErr.ErrorMessage, httpErr.Remedy)
		return
	}
	f.error(w, http.StatusServiceUnavailable, "pivb agent unavailable: "+err.Error(), "start `pivb serve` and retry")
}

func (f *Frontend) text(w http.ResponseWriter, value string) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprint(w, value)
}

func (f *Frontend) error(w http.ResponseWriter, status int, message, remedy string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message, "remedy": remedy})
}

func (f *Frontend) expiryNotification(alias string, expiry time.Time, remaining int64) {
	f.mu.Lock()
	if f.notifiedExpiry.Equal(expiry) {
		f.mu.Unlock()
		return
	}
	f.notifiedExpiry = expiry
	f.mu.Unlock()
	minutes := (remaining + 59) / 60
	f.notify(fmt.Sprintf("token for %s expires in %dm — `pivb renew`", alias, minutes))
}

func (f *Frontend) notify(message string) {
	if len(f.Notify) == 0 {
		return
	}
	args := append(append([]string(nil), f.Notify[1:]...), message)
	cmd := exec.Command(f.Notify[0], args...)
	if err := cmd.Start(); err != nil {
		f.logger().Warn("desktop notification failed", "error", err)
		return
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			f.logger().Warn("desktop notification failed", "error", err)
		}
	}()
}

func (f *Frontend) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Frontend) logger() *slog.Logger {
	if f.Logger != nil {
		return f.Logger
	}
	return slog.Default()
}
