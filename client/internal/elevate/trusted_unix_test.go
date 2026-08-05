//go:build !windows

package elevate

import (
	"os"
	"path/filepath"
	"testing"
)

// ownerOnlyDir is t.TempDir() with the write bits tightened. testing creates its
// numbered directory with 0777 minus the umask, so under the common 002 umask it
// is group-writable and would fail the check under test on its own.
func ownerOnlyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	return dir
}

// writeExecutable creates a plain executable file, the shape trustedSelf checks.
func writeExecutable(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "netbird-ui")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	return path
}

func TestCheckOnlyOwnerWritableAcceptsOwnerOnly(t *testing.T) {
	if err := checkOnlyOwnerWritable(writeExecutable(t, ownerOnlyDir(t))); err != nil {
		t.Errorf("owner-only writable executable rejected: %v", err)
	}
}

func TestCheckOnlyOwnerWritableRejectsWorldWritableFile(t *testing.T) {
	path := writeExecutable(t, ownerOnlyDir(t))
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := checkOnlyOwnerWritable(path); err == nil {
		t.Error("world-writable executable accepted")
	}
}

// The permission policy on its own, without a filesystem to arrange: whether the
// group has been vouched for is the only thing that makes group write acceptable.
func TestWriteBitsAllow(t *testing.T) {
	tests := []struct {
		name         string
		perm         os.FileMode
		sticky       bool
		groupAllowed bool
		wantErr      bool
	}{
		{name: "owner only", perm: 0o755},
		{name: "group write in a private group", perm: 0o775, groupAllowed: true},
		{name: "group write in a shared group", perm: 0o775, wantErr: true},
		{name: "world write", perm: 0o777, groupAllowed: true, wantErr: true},
		{name: "world write on a sticky directory", perm: 0o777, sticky: true},
		{name: "group write on a sticky directory", perm: 0o775, sticky: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := writeBitsAllow("/path", tt.perm, tt.sticky, tt.groupAllowed)
			if tt.wantErr {
				if err == nil {
					t.Errorf("writeBitsAllow(%v, sticky=%v, groupAllowed=%v) = nil, want an error",
						tt.perm, tt.sticky, tt.groupAllowed)
				}
				return
			}
			if err != nil {
				t.Errorf("writeBitsAllow(%v, sticky=%v, groupAllowed=%v) = %v, want nil",
					tt.perm, tt.sticky, tt.groupAllowed, err)
			}
		})
	}
}

// A build under a home directory on a distribution with a 002 umask, which is what
// a locally built or tarball-installed binary looks like. Its group has no members
// but its owner, so it is as good as owner-only.
func TestCheckOnlyOwnerWritableAcceptsOwnPrivateGroup(t *testing.T) {
	if !groupWriteAllowed(uint32(os.Getuid()), uint32(os.Getgid())) {
		t.Skip("the test user's primary group is shared, so there is nothing to assert here")
	}

	dir := ownerOnlyDir(t)
	path := writeExecutable(t, dir)
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	if err := os.Chmod(path, 0o775); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := checkOnlyOwnerWritable(path); err != nil {
		t.Errorf("executable group-writable in its owner's private group rejected: %v", err)
	}
}

// A writable directory is as good as a writable file: whoever can write the
// directory can put a different binary at the same path.
func TestCheckOnlyOwnerWritableRejectsWritableDirectory(t *testing.T) {
	dir := filepath.Join(ownerOnlyDir(t), "bin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := writeExecutable(t, dir)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}

	if err := checkOnlyOwnerWritable(path); err == nil {
		t.Error("executable in a world-writable directory accepted")
	}
}

// A sticky world-writable directory is exempt: the sticky bit is what stops one
// user replacing another's entries. /tmp is why this matters.
func TestCheckOnlyOwnerWritableAcceptsStickyDirectory(t *testing.T) {
	dir := filepath.Join(ownerOnlyDir(t), "sticky")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := writeExecutable(t, dir)
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}

	if err := checkOnlyOwnerWritable(path); err != nil {
		t.Errorf("executable in a sticky directory rejected: %v", err)
	}
}

func TestCheckOnlyOwnerWritableRejectsMissingFile(t *testing.T) {
	if err := checkOnlyOwnerWritable(filepath.Join(ownerOnlyDir(t), "absent")); err == nil {
		t.Error("missing executable accepted")
	}
}
