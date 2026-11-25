//go:build darwin && !ios

package server

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestValidateAgentPeerAcceptsOwnUID confirms the happy path: a Unix
// socket whose peer is the current process must validate when the
// expected uid matches the process's own. Both sides of a unix-socket
// pair share the same kernel cred, so this exercises the real getsockopt
// LOCAL_PEERCRED path.
func TestValidateAgentPeerAcceptsOwnUID(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if err := validateAgentPeer(c, uint32(os.Getuid())); err != nil {
		t.Fatalf("validateAgentPeer rejected own uid: %v", err)
	}
	wg.Wait()
}

// TestValidateAgentPeerRejectsWrongUID ensures the validator fails when
// the expected uid differs from the kernel-reported peer uid. This is
// the path that catches a hostile process that won the listen race.
func TestValidateAgentPeerRejectsWrongUID(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Pick a uid the test process certainly isn't running as.
	wrongUID := uint32(os.Getuid()) + 1
	err = validateAgentPeer(c, wrongUID)
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "does not match expected") {
		t.Fatalf("error should mention uid mismatch, got: %v", err)
	}
	wg.Wait()
}

// TestValidateAgentPeerRejectsNonUnix protects against being handed a
// non-Unix-socket connection (the validator can't enforce anything on
// e.g. a *net.TCPConn so it must refuse rather than silently pass).
func TestValidateAgentPeerRejectsNonUnix(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer c.Close()
	if err := validateAgentPeer(c, 0); err == nil {
		t.Fatal("expected refusal on non-unix conn, got nil")
	}
	wg.Wait()
}
