//go:build android

package android

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/client/internal/filedrop"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

type stubStream struct {
	reader io.Reader
	closed bool
	// chunk caps what one call returns, so the reader's buffering is exercised
	// rather than every read landing in a single hop.
	chunk int
}

type stubSource struct {
	content string
	offsets []int64
	chunk   int
}

func (s *stubStream) NextChunk(max int) ([]byte, error) {
	if s.chunk > 0 && s.chunk < max {
		max = s.chunk
	}
	buf := make([]byte, max)

	n, err := s.reader.Read(buf)
	if errors.Is(err, io.EOF) || n == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *stubStream) Close() error {
	s.closed = true
	return nil
}

func (s *stubSource) Open(offset int64) (SourceStream, error) {
	s.offsets = append(s.offsets, offset)
	return &stubStream{reader: strings.NewReader(s.content[offset:]), chunk: s.chunk}, nil
}

func TestPayloadSourceReassemblesChunks(t *testing.T) {
	for name, chunk := range map[string]int{
		"one hop":     0,
		"three bytes": 3,
		"one byte":    1,
	} {
		t.Run(name, func(t *testing.T) {
			source := &stubSource{content: "hello world", chunk: chunk}

			payloads := NewFileDropPayloads()
			if err := payloads.AddFile("greeting.txt", 11, "text/plain", source); err != nil {
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
		})
	}
}

func TestPayloadSourceHonoursOffset(t *testing.T) {
	source := &stubSource{content: "hello world"}

	payloads := NewFileDropPayloads()
	if err := payloads.AddFile("greeting.txt", 11, "", source); err != nil {
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
	if len(source.offsets) != 1 || source.offsets[0] != 6 {
		t.Fatalf("expected one open at offset 6, got %v", source.offsets)
	}
}

func TestPayloadRejectsMissingSourceAndOversizedText(t *testing.T) {
	payloads := NewFileDropPayloads()

	if err := payloads.AddFile("no-source.bin", 1, "", nil); err == nil {
		t.Fatal("expected an error for a file without a source")
	}
	if err := payloads.AddFile("", 1, "", &stubSource{}); err == nil {
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

	if fd.DestinationDir() != "" {
		t.Fatalf("expected no destination before seeding, got %q", fd.DestinationDir())
	}

	ensureFileDropDestination(fd)

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

func TestProfileLocationForSplitsConfigPath(t *testing.T) {
	root := t.TempDir()

	dir, id, err := profileLocationFor(filepath.Join(root, defaultConfigFilename))
	if err != nil {
		t.Fatalf("default profile: %v", err)
	}
	if dir != root || id != profilemanager.DefaultProfileName {
		t.Fatalf("default profile = (%q, %q), want (%q, %q)", dir, id, root, profilemanager.DefaultProfileName)
	}

	named := filepath.Join(root, profilesSubdir, "aaaaaaaabbbbbbbbccccccccdddddddd.json")
	dir, id, err = profileLocationFor(named)
	if err != nil {
		t.Fatalf("named profile: %v", err)
	}
	if dir != root || id != "aaaaaaaabbbbbbbbccccccccdddddddd" {
		t.Fatalf("named profile = (%q, %q), want (%q, %q)", dir, id, root, "aaaaaaaabbbbbbbbccccccccdddddddd")
	}

	for _, path := range []string{"", filepath.Join(root, "stray.json"), filepath.Join(root, profilesSubdir, "not-an-id!.json")} {
		if _, _, err := profileLocationFor(path); err == nil {
			t.Fatalf("expected an error for %q", path)
		}
	}
}

func writeTestProfile(t *testing.T, configDir, id string) {
	t.Helper()

	pm := NewProfileManager(configDir)
	if _, err := pm.serviceMgr.ProfilePrefs(profilemanager.ID(id), androidUsername); err != nil {
		t.Fatalf("resolve prefs for %s: %v", id, err)
	}
}
