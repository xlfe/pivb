package procinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// writeStat plants one process in a fake /proc. The line follows the kernel
// layout the parser depends on: pid, "(comm)", state, ppid, then fields this
// package never reads.
func writeStat(t *testing.T, root string, pid int32, comm string, ppid int32) {
	t.Helper()
	dir := filepath.Join(root, strconv.FormatInt(int64(pid), 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create fake /proc/%d: %v", pid, err)
	}
	line := fmt.Sprintf("%d (%s) S %d 4321 4321 0 -1 4194304 153 0 0 0 0 0 20 0 1 0 10055162\n", pid, comm, ppid)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o600); err != nil {
		t.Fatalf("write fake /proc/%d/stat: %v", pid, err)
	}
}

// fakeProc is a three-deep chain whose comms exercise the two things that make
// stat parsing subtle: a space and a nested parenthesis inside comm.
func fakeProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeStat(t, root, 4321, "gcloud", 777)
	writeStat(t, root, 777, "tmux: server", 1201)
	writeStat(t, root, 1201, "sh (deleted)", 1)
	return root
}

func TestChain(t *testing.T) {
	full := []Entry{{PID: 4321, Comm: "gcloud"}, {PID: 777, Comm: "tmux: server"}, {PID: 1201, Comm: "sh (deleted)"}}
	tests := []struct {
		name     string
		pid      int32
		maxDepth int
		want     []Entry
	}{
		{name: "walks to init and stops before it", pid: 4321, maxDepth: 5, want: full},
		{name: "depth cap truncates", pid: 4321, maxDepth: 2, want: full[:2]},
		{name: "depth of one", pid: 4321, maxDepth: 1, want: full[:1]},
		{name: "no depth at all", pid: 4321, maxDepth: 0},
		{name: "init itself is not a chain", pid: 1, maxDepth: 5},
		{name: "unknown pid", pid: 999, maxDepth: 5},
	}
	root := fakeProc(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Chain(root, tc.pid, tc.maxDepth)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Chain(%d, %d) = %+v, want %+v", tc.pid, tc.maxDepth, got, tc.want)
			}
		})
	}
}

// TestChainTruncatesAtUnreadableLink is the fail-soft contract: a parent that
// has exited, or one hidden by ProtectProc, ends the chain instead of the walk.
func TestChainTruncatesAtUnreadableLink(t *testing.T) {
	t.Run("missing parent", func(t *testing.T) {
		root := t.TempDir()
		writeStat(t, root, 4321, "gcloud", 777)
		// 777 is never planted: the chain stops at what it could read.
		want := []Entry{{PID: 4321, Comm: "gcloud"}}
		if got := Chain(root, 4321, 5); !reflect.DeepEqual(got, want) {
			t.Errorf("Chain = %+v, want %+v", got, want)
		}
	})

	t.Run("malformed stat", func(t *testing.T) {
		root := t.TempDir()
		writeStat(t, root, 4321, "gcloud", 777)
		dir := filepath.Join(root, "777")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte("777 no-parens here\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		want := []Entry{{PID: 4321, Comm: "gcloud"}}
		if got := Chain(root, 4321, 5); !reflect.DeepEqual(got, want) {
			t.Errorf("Chain = %+v, want %+v", got, want)
		}
	})
}

// TestChainReadsRealProc keeps the parser honest against the kernel's own
// format rather than only against this file's fixtures.
func TestChainReadsRealProc(t *testing.T) {
	if _, err := os.ReadFile("/proc/self/stat"); err != nil {
		t.Skipf("no readable /proc on this host: %v", err)
	}
	got := Chain("", int32(os.Getpid()), 3)
	if len(got) == 0 {
		t.Fatal("Chain over the real /proc returned nothing for this process")
	}
	if got[0].PID != int32(os.Getpid()) {
		t.Errorf("first entry = %+v, want this process (%d)", got[0], os.Getpid())
	}
	if got[0].Comm == "" {
		t.Errorf("first entry = %+v, want a comm", got[0])
	}
}

func TestFormatChain(t *testing.T) {
	tests := []struct {
		name    string
		entries []Entry
		want    string
	}{
		{name: "empty"},
		{name: "one entry", entries: []Entry{{PID: 4321, Comm: "gcloud"}}, want: "4321(gcloud)"},
		{
			name:    "full chain",
			entries: []Entry{{PID: 4321, Comm: "gcloud"}, {PID: 777, Comm: "fish"}, {PID: 1201, Comm: "tmux: server"}},
			want:    "4321(gcloud)<-777(fish)<-1201(tmux: server)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatChain(tc.entries); got != tc.want {
				t.Errorf("FormatChain(%+v) = %q, want %q", tc.entries, got, tc.want)
			}
		})
	}
}
