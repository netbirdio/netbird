//go:build ios

package NetBirdSDK

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/client/internal/filedrop"
)

func TestPayloadFileReadsFromPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "greeting.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	payloads := NewFileDropPayloads()
	if err := payloads.AddFile("greeting.txt", 11, "text/plain", path); err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	if payloads.Length() != 1 {
		t.Fatalf("expected 1 payload, got %d", payloads.Length())
	}

	stream, err := payloads.items[0].Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q, want %q", got, "hello world")
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestPayloadFileHonoursOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "greeting.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	payloads := NewFileDropPayloads()
	if err := payloads.AddFile("greeting.txt", 11, "", path); err != nil {
		t.Fatalf("AddFile: %v", err)
	}

	stream, err := payloads.items[0].Open(6)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer stream.Close()

	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "world" {
		t.Fatalf("got %q, want %q", got, "world")
	}
}

func TestPayloadRejectsMissingPathAndOversizedText(t *testing.T) {
	payloads := NewFileDropPayloads()

	if err := payloads.AddFile("no-path.bin", 1, "", ""); err == nil {
		t.Fatal("expected an error for a file without a path")
	}
	if err := payloads.AddFile("", 1, "", "/tmp/x"); err == nil {
		t.Fatal("expected an error for an empty file name")
	}
	if err := payloads.AddText("big", strings.Repeat("x", filedrop.MaxInlineTextSize+1)); err == nil {
		t.Fatal("expected an error for oversized text")
	}
	if payloads.Length() != 0 {
		t.Fatalf("expected no payloads, got %d", payloads.Length())
	}
}

func TestFileDropPersistsSettingsPerProfile(t *testing.T) {
	configDir := t.TempDir()
	writeTestProfile(t, configDir, "aaaaaaaabbbbbbbbccccccccdddddddd")
	writeTestProfile(t, configDir, "11111111222222223333333344444444")

	first, err := NewFileDrop(configDir, "aaaaaaaabbbbbbbbccccccccdddddddd")
	if err != nil {
		t.Fatalf("NewFileDrop: %v", err)
	}
	defer first.Close()

	if err := first.SetMode(FileDropModeAutoAccept); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	if err := first.SetPeerRule("peer-key", FileDropRuleBlock); err != nil {
		t.Fatalf("SetPeerRule: %v", err)
	}

	second, err := NewFileDrop(configDir, "11111111222222223333333344444444")
	if err != nil {
		t.Fatalf("NewFileDrop: %v", err)
	}
	defer second.Close()

	if got := second.Mode(); got != FileDropModeAsk {
		t.Fatalf("second profile mode = %d, want the default %d", got, FileDropModeAsk)
	}
	if got := second.PeerRule("peer-key"); got != FileDropRuleDefault {
		t.Fatalf("second profile rule = %d, want %d", got, FileDropRuleDefault)
	}

	reopened, err := NewFileDrop(configDir, "aaaaaaaabbbbbbbbccccccccdddddddd")
	if err != nil {
		t.Fatalf("NewFileDrop: %v", err)
	}
	defer reopened.Close()

	if got := reopened.Mode(); got != FileDropModeAutoAccept {
		t.Fatalf("reopened mode = %d, want %d", got, FileDropModeAutoAccept)
	}
	if got := reopened.PeerRule("peer-key"); got != FileDropRuleBlock {
		t.Fatalf("reopened rule = %d, want %d", got, FileDropRuleBlock)
	}
}

func TestFileDropSeedsDefaultDestination(t *testing.T) {
	configDir := t.TempDir()
	writeTestProfile(t, configDir, "aaaaaaaabbbbbbbbccccccccdddddddd")

	fd, err := NewFileDrop(configDir, "aaaaaaaabbbbbbbbccccccccdddddddd")
	if err != nil {
		t.Fatalf("NewFileDrop: %v", err)
	}
	defer fd.Close()

	want := filepath.Join(configDir, filedropDataSubdir, "aaaaaaaabbbbbbbbccccccccdddddddd", "incoming")
	if got := fd.DestinationDir(); got != want {
		t.Fatalf("destination = %q, want %q", got, want)
	}
}

func TestFileDropSendWithoutTunnelFails(t *testing.T) {
	configDir := t.TempDir()
	writeTestProfile(t, configDir, "aaaaaaaabbbbbbbbccccccccdddddddd")

	fd, err := NewFileDrop(configDir, "aaaaaaaabbbbbbbbccccccccdddddddd")
	if err != nil {
		t.Fatalf("NewFileDrop: %v", err)
	}
	defer fd.Close()

	payloads := NewFileDropPayloads()
	if err := payloads.AddText("note", "hi"); err != nil {
		t.Fatalf("AddText: %v", err)
	}

	if _, err := fd.Send("peer-key", "peer", "100.64.0.2", payloads); !errors.Is(err, filedrop.ErrNotConnected) {
		t.Fatalf("Send error = %v, want %v", err, filedrop.ErrNotConnected)
	}
	if _, err := fd.Send("peer-key", "peer", "100.64.0.2", NewFileDropPayloads()); err == nil {
		t.Fatal("expected an error when there is nothing to send")
	}
	if _, err := fd.Send("peer-key", "peer", "not-an-ip", payloads); err == nil {
		t.Fatal("expected an error for an unparseable peer address")
	}
}

func writeTestProfile(t *testing.T, configDir, id string) {
	t.Helper()

	if _, err := NewProfileManager(configDir).impl.ProfilePrefs(id); err != nil {
		t.Fatalf("resolve prefs for %s: %v", id, err)
	}
}
