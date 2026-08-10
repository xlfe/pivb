package pivsigner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultRecoveryGrace = 500 * time.Millisecond
	defaultRecoveryLimit = 2 * time.Second
	diagnosticScanLimit  = 250 * time.Millisecond
	probeOpenLimit       = 250 * time.Millisecond
	minimumCallerTime    = time.Second
	handoffWindow        = 10 * time.Second
	handoffCapacity      = 2
	maxGnuPGOutput       = 4 << 10
)

type OperationOrigin string

const (
	OriginUnclassified OperationOrigin = "unclassified"
	OriginForwarded    OperationOrigin = "forwarded"
	OriginAgentSession OperationOrigin = "agent-session"
	OriginLocalWIF     OperationOrigin = "local-wif"
	OriginUnlock       OperationOrigin = "unlock"
)

type operationInfo struct {
	Origin OperationOrigin
	ID     string
}

type operationKey struct{}

var localOperationSequence atomic.Uint64

// WithOperation carries correlation and cooperative-throttle context to the
// hardware layer. It is operational policy, not an authorization boundary.
func WithOperation(ctx context.Context, origin OperationOrigin, id string) context.Context {
	return context.WithValue(ctx, operationKey{}, operationInfo{Origin: origin, ID: id})
}

func operationFrom(ctx context.Context, fallback OperationOrigin) operationInfo {
	op, _ := ctx.Value(operationKey{}).(operationInfo)
	if op.Origin == "" {
		op.Origin = fallback
	}
	if op.ID == "" {
		op.ID = fmt.Sprintf("pivb-%016x", localOperationSequence.Add(1))
	}
	return op
}

type scdaemonState string

const (
	scdaemonRunning scdaemonState = "true"
	scdaemonStopped scdaemonState = "false"
	scdaemonUnknown scdaemonState = "unknown"
)

// ContentionError distinguishes a bounded, measured recovery failure from a
// generic signing error. Initial and final causes remain independently
// inspectable in logs and the initial cause remains the unwrap target.
type ContentionError struct {
	Initial           error
	Final             error
	Elapsed           time.Duration
	Attempts          int
	ProbeWaits        int
	SCDRunning        scdaemonState
	SCDEvidence       string
	InspectionError   error
	HandoffAttempted  bool
	HandoffError      error
	EverSelfHeld      bool
	LastSelfHeld      bool
	EverBlockedInOpen bool
	CooldownRemaining time.Duration
}

func (e *ContentionError) Error() string {
	state := "persistent external smart-card contention"
	if e.CooldownRemaining > 0 {
		state = fmt.Sprintf("smart-card hand-off is throttled; retry in %s", displayDelay(e.CooldownRemaining))
	}
	if e.LastSelfHeld {
		state = "an in-process PIV session still holds the smart card"
	}
	return fmt.Sprintf("%s after %s (%d open attempts, %d probe waits): initial error: %v; final error: %v", state, e.Elapsed.Round(time.Millisecond), e.Attempts, e.ProbeWaits, e.Initial, e.Final)
}

func (e *ContentionError) Unwrap() error { return e.Initial }

// acquisitionHandledError prevents Sign's late-stage whole-attempt retry
// from re-running a recovery episode already exhausted by acquisition. It
// deliberately unwraps to a sharing violation, so callers that only classify
// the PC/SC cause still receive the correct busy response.
type acquisitionHandledError struct{ err error }

func (e *acquisitionHandledError) Error() string { return e.err.Error() }
func (e *acquisitionHandledError) Unwrap() error { return e.err }

type recoveryBudget struct {
	started          time.Time
	limit            time.Duration
	blockedOpenStart uint64
	diagnosed        bool
}

func (h *Hardware) newRecoveryBudget() *recoveryBudget {
	limit := h.recoveryLimit
	if limit <= 0 {
		limit = defaultRecoveryLimit
	}
	return &recoveryBudget{limit: limit, blockedOpenStart: h.blockedOpenEvents.Load()}
}

func (b *recoveryBudget) remaining(now time.Time) time.Duration {
	if b.started.IsZero() {
		b.started = now
	}
	remaining := b.limit - now.Sub(b.started)
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (h *Hardware) acquireCard(ctx context.Context, op operationInfo, budget *recoveryBudget) (card, uint32, error) {
	yk, serial, err := h.openSelectedContext(ctx)
	if err == nil || !IsSharingViolation(err) {
		return yk, serial, err
	}
	// The diagnostic rescan is part of, not additional to, the two-second
	// recovery budget.
	remaining := budget.remaining(h.nowTime())
	h.logSelectionFailure(op, err)
	if !budget.diagnosed && remaining > 0 {
		budget.diagnosed = true
		h.diagnosticRescan(ctx, op)
	}
	yk, serial, contention := h.recoverSharing(ctx, op, err, budget)
	if contention != nil {
		return nil, 0, &acquisitionHandledError{err: contention}
	}
	return yk, serial, nil
}

func (h *Hardware) logSelectionFailure(op operationInfo, err error) {
	attrs := []any{"operation", op.Origin, "operation_id", op.ID, "error", err}
	var selection *SelectionError
	if errors.As(err, &selection) {
		results := make([]string, 0, len(selection.Failures))
		for _, failure := range selection.Failures {
			results = append(results, fmt.Sprintf("%s:%s:%v", failure.Reader, failure.Stage, failure.Err))
		}
		attrs = append(attrs, "readers", selection.Readers, "reader_results", results, "configured_serials", selection.Wanted)
	}
	h.logger().Warn("smart-card acquisition failed", attrs...)
}

func (h *Hardware) diagnosticRescan(ctx context.Context, op operationInfo) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < minimumCallerTime {
		h.logger().Info("skipping smart-card diagnostic rescan near caller deadline", "operation", op.Origin, "operation_id", op.ID)
		return
	}
	if !h.diagnosticWorker.CompareAndSwap(false, true) {
		h.logger().Info("skipping smart-card diagnostic rescan while the process worker is still active", "operation", op.Origin, "operation_id", op.ID)
		return
	}
	result := make(chan openResult, 1)
	go func() {
		defer h.diagnosticWorker.Store(false)
		yk, serial, err := h.openSelectedUntracked()
		if yk != nil {
			_ = yk.Close()
		}
		result <- openResult{serial: serial, err: err}
	}()
	timer := time.NewTimer(diagnosticScanLimit)
	defer timer.Stop()
	select {
	case scan := <-result:
		h.logger().Info("smart-card diagnostic rescan completed", "operation", op.Origin, "operation_id", op.ID, "configured_serial_reachable", scan.serial, "error", scan.err, "scan_truncated", false)
	case <-timer.C:
		h.blockedOpenEvents.Add(1)
		h.logger().Warn("smart-card diagnostic rescan exceeded its latency cap", "operation", op.Origin, "operation_id", op.ID, "scan_truncated", true, "ever_blocked_in_open", true)
	case <-ctx.Done():
	}
}

func (h *Hardware) recoverSharing(ctx context.Context, op operationInfo, initial error, budget *recoveryBudget) (card, uint32, *ContentionError) {
	started := h.nowTime()
	remaining := budget.remaining(started)
	if remaining <= 0 {
		return nil, 0, h.contentionError(initial, initial, budget, 1, 0, scdaemonUnknown, "", nil, false, nil, false, 0)
	}
	grace := h.recoveryGrace
	if grace <= 0 {
		grace = defaultRecoveryGrace
	}
	graceDeadline := started.Add(grace)
	delays := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond}
	delayIndex := 0
	attempts := 1
	probeWaits := 0
	lastErr := initial
	state := scdaemonUnknown
	var scdEvidence string
	inspected := false
	handoffAttempted := false
	var inspectionErr error
	var handoffErr error
	stickySelf := h.hasSelfHolder()
	everSelf := stickySelf
	lastSelfObserved := stickySelf
	var cooldownUntil time.Time

	h.logger().Warn("confirmed PC/SC sharing violation; polling before any scdaemon hand-off", "operation", op.Origin, "operation_id", op.ID, "initial_error", initial, "recovery_budget", remaining)
	for {
		now := h.nowTime()
		remaining = budget.remaining(now)
		if remaining <= 0 || ctx.Err() != nil {
			break
		}
		delay := delays[delayIndex]
		if delayIndex < len(delays)-1 {
			delayIndex++
		}
		if !inspected && now.Before(graceDeadline) && now.Add(delay).After(graceDeadline) {
			delay = graceDeadline.Sub(now)
		}
		if delay > remaining {
			delay = remaining
		}
		if err := h.sleepContext(ctx, delay); err != nil {
			lastErr = err
			break
		}

		probeLimit := probeOpenLimit
		if r := budget.remaining(h.nowTime()); probeLimit > r {
			probeLimit = r
		}
		if probeLimit <= 0 {
			break
		}
		probeCtx, cancel := context.WithTimeout(ctx, probeLimit)
		probeWaits++
		yk, serial, startedProbes, probeErr := h.openProbeContext(probeCtx)
		cancel()
		attempts += startedProbes
		if probeErr == nil {
			h.logger().Info("smart-card contention cleared", "operation", op.Origin, "operation_id", op.ID, "elapsed", h.nowTime().Sub(started), "attempts", attempts, "probe_waits", probeWaits, "scd_running", state, "handoff_attempted", handoffAttempted)
			return yk, serial, nil
		}
		lastErr = probeErr
		currentSelf := h.hasSelfHolder()
		if currentSelf {
			stickySelf = true
			everSelf = true
		}

		now = h.nowTime()
		if stickySelf && lastSelfObserved && !currentSelf && inspected {
			// Hand-off remains suppressed for this episode, but refresh the
			// measured final blocker after PIVB's own session disappears.
			inspectLimit := minDuration(500*time.Millisecond, budget.remaining(now))
			if inspectLimit > 0 {
				reinspectCtx, reinspectCancel := context.WithTimeout(ctx, inspectLimit)
				state, scdEvidence, inspectionErr = h.inspectScdaemon(reinspectCtx)
				reinspectCancel()
				h.logger().Info("re-inspected scdaemon after in-process card holder exited", "operation", op.Origin, "operation_id", op.ID, "scd_running", state, "scd_response", scdEvidence, "error", inspectionErr)
			}
		}
		lastSelfObserved = currentSelf
		if inspected || now.Before(graceDeadline) {
			continue
		}
		inspected = true
		inspectLimit := 500 * time.Millisecond
		if r := budget.remaining(now); inspectLimit > r {
			inspectLimit = r
		}
		if inspectLimit <= 0 {
			continue
		}
		inspectCtx, inspectCancel := context.WithTimeout(ctx, inspectLimit)
		state, scdEvidence, inspectionErr = h.inspectScdaemon(inspectCtx)
		inspectCancel()
		h.logger().Info("inspected scdaemon before smart-card hand-off", "operation", op.Origin, "operation_id", op.ID, "scd_running", state, "scd_response", scdEvidence, "error", inspectionErr)
		if stickySelf || state == scdaemonStopped {
			continue
		}
		handoffLimit := minDuration(500*time.Millisecond, budget.remaining(h.nowTime()))
		if handoffLimit <= 0 {
			continue
		}
		allowed, retryAfter := h.reserveHandoff(op, h.nowTime())
		if !allowed {
			cooldownUntil = h.nowTime().Add(retryAfter)
			h.logger().Warn("skipping scdaemon hand-off during cooperative cooldown", "operation", op.Origin, "operation_id", op.ID, "retry_after", retryAfter)
			continue
		}
		handoffAttempted = true
		handoffCtx, handoffCancel := context.WithTimeout(ctx, handoffLimit)
		handoffErr = h.handoffScdaemon(handoffCtx)
		handoffCancel()
		if handoffErr != nil {
			h.logger().Warn("scdaemon hand-off failed; continuing bounded polling", "operation", op.Origin, "operation_id", op.ID, "scd_running", state, "scd_response", scdEvidence, "error", handoffErr)
		} else {
			h.logger().Warn("requested scdaemon hand-off; PC/SC release is asynchronous", "operation", op.Origin, "operation_id", op.ID, "scd_running", state, "scd_response", scdEvidence)
		}
		delayIndex = 0
	}
	cooldownRemaining := cooldownUntil.Sub(h.nowTime())
	if cooldownRemaining < 0 {
		cooldownRemaining = 0
	}
	contention := h.contentionError(initial, lastErr, budget, attempts, probeWaits, state, scdEvidence, inspectionErr, handoffAttempted, handoffErr, everSelf, cooldownRemaining)
	h.logger().Warn("smart-card contention recovery exhausted", "operation", op.Origin, "operation_id", op.ID,
		"initial_error", initial, "final_error", lastErr, "elapsed", contention.Elapsed, "attempts", attempts, "probe_waits", probeWaits,
		"scd_running", state, "scd_response", scdEvidence, "inspection_error", inspectionErr, "handoff_attempted", handoffAttempted, "handoff_error", handoffErr,
		"ever_self_held", everSelf, "last_self_held", contention.LastSelfHeld,
		"ever_blocked_in_open", contention.EverBlockedInOpen, "cooldown_remaining", cooldownRemaining)
	return nil, 0, contention
}

func (h *Hardware) contentionError(initial, final error, budget *recoveryBudget, attempts, probeWaits int, state scdaemonState, scdEvidence string, inspectionErr error, attempted bool, handoffErr error, everSelf bool, cooldown time.Duration) *ContentionError {
	return &ContentionError{
		Initial: initial, Final: final, Elapsed: h.nowTime().Sub(budget.started), Attempts: attempts, ProbeWaits: probeWaits,
		SCDRunning: state, SCDEvidence: scdEvidence, InspectionError: inspectionErr, HandoffAttempted: attempted, HandoffError: handoffErr,
		EverSelfHeld: everSelf, LastSelfHeld: h.hasSelfHolder(),
		EverBlockedInOpen: h.blockedOpenEvents.Load() > budget.blockedOpenStart || h.openWorkers.Load() > 0,
		CooldownRemaining: cooldown,
	}
}

func (h *Hardware) reserveHandoff(op operationInfo, now time.Time) (bool, time.Duration) {
	if op.Origin == OriginLocalWIF || op.Origin == OriginUnlock {
		return true, 0
	}
	h.recoveryMu.Lock()
	defer h.recoveryMu.Unlock()
	cutoff := now.Add(-handoffWindow)
	kept := h.handoffs[:0]
	for _, at := range h.handoffs {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	h.handoffs = kept
	if len(h.handoffs) >= handoffCapacity {
		return false, h.handoffs[0].Add(handoffWindow).Sub(now)
	}
	h.handoffs = append(h.handoffs, now)
	return true, 0
}

func (h *Hardware) inspectScdaemon(ctx context.Context) (scdaemonState, string, error) {
	if h.inspectSCD != nil {
		state, err := h.inspectSCD(ctx)
		return state, "injected", err
	}
	out, err := h.runGnuPG(ctx, "gpg-connect-agent", "--no-autostart", "GETINFO scd_running", "/bye")
	state, classifyErr := classifyScdaemonOutput(out, err)
	return state, firstLine(string(out)), classifyErr
}

// classifyScdaemonOutput interprets the Assuan status emitted by
// gpg-connect-agent. With --no-autostart the program intentionally exits zero
// when no agent exists, and an Assuan ERR response also does not determine the
// process exit status, so exit status alone cannot answer this question.
func classifyScdaemonOutput(out []byte, runErr error) (scdaemonState, error) {
	if runErr != nil {
		return scdaemonUnknown, runErr
	}
	text := strings.TrimSpace(string(out))
	lower := strings.ToLower(text)
	if strings.Contains(lower, "no gpg-agent running in this session") {
		return scdaemonStopped, nil
	}
	hasOK := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ERR ") {
			return scdaemonStopped, nil
		}
		if line == "OK" || strings.HasPrefix(line, "OK ") {
			hasOK = true
		}
	}
	if hasOK {
		return scdaemonRunning, nil
	}
	return scdaemonUnknown, errors.New("gpg-connect-agent returned no recognizable Assuan status")
}

func (h *Hardware) handoffScdaemon(ctx context.Context) error {
	if h.handoff != nil {
		return h.handoff(ctx)
	}
	_, err := h.runGnuPG(ctx, "gpgconf", "--kill", "scdaemon")
	return err
}

func (h *Hardware) runGnuPG(ctx context.Context, program string, args ...string) ([]byte, error) {
	lookPath := exec.LookPath
	if h.lookPath != nil {
		lookPath = h.lookPath
	}
	path, err := lookPath(program)
	if err != nil {
		return nil, err
	}
	home := h.resolvedGnuPGHome()
	if home.command != "" {
		if _, statErr := os.Stat(home.command); statErr != nil {
			h.logger().Warn("selected GnuPG home is unavailable during smart-card recovery", "gnupg_home", home.display, "gnupg_home_source", home.source, "error", statErr)
		}
		args = append([]string{"--homedir", home.command}, args...)
	}
	out, runErr := h.execute(ctx, path, args, home.command)
	h.logGnuPGDetails(program, path, home, lookPath)
	return out, runErr
}

// PrimeGnuPGDiagnostics logs the recovery binaries, versions, and target socket
// during daemon startup so the first contention episode does not pay this
// diagnostic cost. A top-level command-resolution failure leaves that command's
// latch untouched for first-use fallback. Once a version or socket body starts,
// however, its result is latched even on failure; the socket query runs first so
// the most useful recovery-target evidence gets the shared startup budget.
func (h *Hardware) PrimeGnuPGDiagnostics() {
	lookPath := exec.LookPath
	if h.lookPath != nil {
		lookPath = h.lookPath
	}
	home := h.resolvedGnuPGHome()
	detailCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	for _, program := range []string{"gpg-connect-agent", "gpgconf"} {
		path, err := lookPath(program)
		if err != nil {
			h.logger().Warn("cannot resolve GnuPG recovery command for startup diagnostics", "program", program, "gnupg_home", home.display, "gnupg_home_source", home.source, "error", err)
			continue
		}
		h.logGnuPGDetailsContext(detailCtx, program, path, home, lookPath)
	}
}

func (h *Hardware) logGnuPGDetails(program, path string, home gnupgHomeResolution, lookPath func(string) (string, error)) {
	detailCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	h.logGnuPGDetailsContext(detailCtx, program, path, home, lookPath)
}

func (h *Hardware) logGnuPGDetailsContext(detailCtx context.Context, program, path string, home gnupgHomeResolution, lookPath func(string) (string, error)) {
	logOnce := &h.gpgconfLogOnce
	if program == "gpg-connect-agent" {
		logOnce = &h.gpgConnectLogOnce
	}
	h.gnupgTargetOnce.Do(func() {
		gpgconfPath, err := lookPath("gpgconf")
		if err != nil {
			h.logger().Warn("cannot resolve gpgconf for GnuPG target diagnostics", "gnupg_home", home.display, "gnupg_home_source", home.source, "error", err)
			return
		}
		args := []string{"--list-dirs", "agent-socket"}
		if home.command != "" {
			args = append([]string{"--homedir", home.command}, args...)
		}
		out, commandErr := h.execute(detailCtx, gpgconfPath, args, home.command)
		h.logger().Info("resolved GnuPG recovery target", "gpgconf_path", gpgconfPath, "gnupg_home", home.display, "gnupg_home_source", home.source, "agent_socket", firstLine(string(out)), "error", commandErr)
	})
	logOnce.Do(func() {
		version, versionErr := h.execute(detailCtx, path, []string{"--version"}, home.command)
		h.logger().Info("resolved GnuPG recovery command", "program", program, "path", path, "gnupg_home", home.display, "gnupg_home_source", home.source, "homedir_forced", home.command != "", "version", firstLine(string(version)), "version_error", versionErr)
	})
}

func (h *Hardware) execute(ctx context.Context, path string, args []string, home string) ([]byte, error) {
	if h.command != nil {
		return h.command(ctx, path, args, home)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = os.Environ()
	if home != "" {
		cmd.Env = replaceEnvironment(cmd.Env, "GNUPGHOME", home)
	}
	return boundOutput(cmd, maxGnuPGOutput)
}

type cappedOutput struct {
	mu        sync.Mutex
	limit     int
	data      []byte
	truncated bool
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := w.limit - len(w.data)
	if remaining > 0 {
		keep := len(p)
		if keep > remaining {
			keep = remaining
		}
		w.data = append(w.data, p[:keep]...)
	}
	if len(p) > remaining {
		w.truncated = true
	}
	// Consume discarded bytes so a verbose child cannot block or receive a
	// broken pipe merely because diagnostics reached their capture limit.
	return len(p), nil
}

func (w *cappedOutput) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := append([]byte(nil), w.data...)
	if !w.truncated {
		return out
	}
	marker := []byte(fmt.Sprintf("\n[output truncated at %d bytes]", w.limit))
	if len(marker) > w.limit {
		marker = marker[:w.limit]
	}
	if len(out)+len(marker) > w.limit {
		out = out[:w.limit-len(marker)]
	}
	return append(out, marker...)
}

func boundOutput(cmd *exec.Cmd, limit int) ([]byte, error) {
	output := &cappedOutput{limit: limit}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	return output.bytes(), err
}

func replaceEnvironment(env []string, name, value string) []string {
	prefix := name + "="
	replaced := false
	result := make([]string, 0, len(env)+1)
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			if !replaced {
				result = append(result, prefix+value)
				replaced = true
			}
			continue
		}
		result = append(result, item)
	}
	if !replaced {
		result = append(result, prefix+value)
	}
	return result
}

type gnupgHomeResolution struct {
	display string
	command string
	source  string
}

func (h *Hardware) resolvedGnuPGHome() gnupgHomeResolution {
	if h.GnuPGHome != "" {
		return gnupgHomeResolution{display: h.GnuPGHome, command: h.GnuPGHome, source: "config"}
	}
	if home := os.Getenv("GNUPGHOME"); home != "" {
		return gnupgHomeResolution{display: home, command: home, source: "environment"}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return gnupgHomeResolution{display: filepath.Join(home, ".gnupg"), source: "gpg-default"}
	}
	return gnupgHomeResolution{source: "gpg-default"}
}

func (h *Hardware) nowTime() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}

func (h *Hardware) sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	if h.sleep != nil {
		return h.sleep(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func firstLine(value string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(value), "\n")
	return line
}
