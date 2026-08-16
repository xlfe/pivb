// Package procinfo resolves best-effort parent-process chains for logging.
// It never fails: any read or parse error truncates the chain.
//
// A chain answers "which process asked" for a human reading the journal. It is
// never an authorization input: PIDs are reused, comm is whatever the process
// called itself, and a parent may exit between the peer check and the walk.
//
// The daemon runs under ProtectProc=invisible and ProcSubset=pid (see
// systemd/pivb.service), so /proc shows it only same-UID processes and entries
// for anything else simply come back absent. That costs nothing here: the
// SO_PEERCRED gate admits only same-UID peers in the first place.
package procinfo

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Entry is one process in a chain.
type Entry struct {
	PID  int32
	Comm string
}

// Chain walks /proc/<pid>/stat ppid links starting at pid and returns at most
// maxDepth entries, stopping as soon as a link is unreadable. procRoot "" means
// "/proc". The walk stops before pid 1: init identifies nothing.
func Chain(procRoot string, pid int32, maxDepth int) []Entry {
	if procRoot == "" {
		procRoot = "/proc"
	}
	var entries []Entry
	for len(entries) < maxDepth && pid > 1 {
		comm, parent, ok := readStat(procRoot, pid)
		if !ok {
			break
		}
		entries = append(entries, Entry{PID: pid, Comm: comm})
		pid = parent
	}
	return entries
}

// FormatChain renders a chain as "4321(gcloud)<-777(fish)<-1201(tmux: server)".
// The result belongs in a single log attribute and never in a log message: comm
// is process-controlled text, and only the handler's own quoting keeps it from
// forging journal structure.
func FormatChain(entries []Entry) string {
	var chain strings.Builder
	for i, entry := range entries {
		if i > 0 {
			chain.WriteString("<-")
		}
		chain.WriteString(strconv.FormatInt(int64(entry.PID), 10))
		chain.WriteByte('(')
		chain.WriteString(entry.Comm)
		chain.WriteByte(')')
	}
	return chain.String()
}

// readStat returns the comm and parent PID recorded in /proc/<pid>/stat. comm
// is the bytes between the first '(' and the last ')': it is process-controlled
// and may itself contain spaces and parentheses, so every later field can only
// be located relative to that last ')'. Past it, field 1 is the run state and
// field 2 is the parent PID.
func readStat(procRoot string, pid int32) (comm string, ppid int32, ok bool) {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.FormatInt(int64(pid), 10), "stat"))
	if err != nil {
		return "", 0, false
	}
	stat := string(raw)
	first := strings.IndexByte(stat, '(')
	last := strings.LastIndexByte(stat, ')')
	if first < 0 || last < first {
		return "", 0, false
	}
	fields := strings.Fields(stat[last+1:])
	if len(fields) < 2 {
		return "", 0, false
	}
	parent, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil || parent < 0 {
		return "", 0, false
	}
	return stat[first+1 : last], int32(parent), true
}
