package filedrop

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePlatformWriter struct {
	written  []byte
	offset   int64
	closed   bool
	writeErr error
	closeErr error
}

type fakePlatformSink struct {
	writers   map[string]*fakePlatformWriter
	prepared  []string
	removed   []string
	cleanups  []int64
	openErr   error
	closeErr  error
	openCalls []string
	delivered string
	label     string
}

func newFakePlatformSink() *fakePlatformSink {
	return &fakePlatformSink{writers: map[string]*fakePlatformWriter{}}
}

func (w *fakePlatformWriter) WriteChunk(p []byte) error {
	if w.writeErr != nil {
		return w.writeErr
	}
	w.written = append(w.written, p...)
	return nil
}

func (w *fakePlatformWriter) Close() error {
	w.closed = true
	return w.closeErr
}

func (w *fakePlatformWriter) Written() int64 {
	return w.offset + int64(len(w.written))
}

func (s *fakePlatformSink) DestinationLabel() string {
	return s.label
}

func (s *fakePlatformSink) Prepare(offerID string) error {
	s.prepared = append(s.prepared, offerID)
	return nil
}

func (s *fakePlatformSink) Received(offerID string, index int) (int64, error) {
	w, ok := s.writers[key(offerID, index)]
	if !ok {
		return 0, nil
	}
	return w.Written(), nil
}

func (s *fakePlatformSink) OpenWriter(offerID string, index int, name string, offset int64, _ int64) (PlatformWriter, error) {
	s.openCalls = append(s.openCalls, name)
	if s.openErr != nil {
		return nil, s.openErr
	}
	w := &fakePlatformWriter{offset: offset, closeErr: s.closeErr}
	s.writers[key(offerID, index)] = w
	return w, nil
}

func (s *fakePlatformSink) Deliver(string) (string, error) {
	return s.delivered, nil
}

func (s *fakePlatformSink) Remove(offerID string) {
	s.removed = append(s.removed, offerID)
}

func (s *fakePlatformSink) Cleanup(maxAgeSeconds int64) {
	s.cleanups = append(s.cleanups, maxAgeSeconds)
}

func key(offerID string, index int) string {
	return fmt.Sprintf("%s:%d", offerID, index)
}

func TestPlatformSinkWritesThroughToTheDestination(t *testing.T) {
	platform := newFakePlatformSink()
	sink, err := NewPlatformSink(platform)
	require.NoError(t, err)

	written, err := sink.Write("offer", 0, "report.bin", 0, strings.NewReader("netbird"), 7)
	require.NoError(t, err)
	assert.Equal(t, int64(7), written)

	w := platform.writers[key("offer", 0)]
	assert.Equal(t, "netbird", string(w.written))
	assert.True(t, w.closed, "the destination must be closed after the write")
	assert.Equal(t, []string{"report.bin"}, platform.openCalls,
		"the announced name must reach the platform, which owns the final naming")
}

func TestPlatformSinkStopsAtTheAnnouncedSize(t *testing.T) {
	platform := newFakePlatformSink()
	sink, err := NewPlatformSink(platform)
	require.NoError(t, err)

	written, err := sink.Write("offer", 0, "x.bin", 0, strings.NewReader("more than announced"), 4)
	require.NoError(t, err)
	assert.Equal(t, int64(4), written, "a sender overrunning its own offer must be cut off")
	assert.Equal(t, "more", string(platform.writers[key("offer", 0)].written))
}

func TestPlatformSinkResumeReportsTheTotal(t *testing.T) {
	platform := newFakePlatformSink()
	sink, err := NewPlatformSink(platform)
	require.NoError(t, err)

	written, err := sink.Write("offer", 0, "x.bin", 3, strings.NewReader("def"), 6)
	require.NoError(t, err)
	assert.Equal(t, int64(6), written,
		"the platform counts from the offset it resumed at, not from this call alone")
}

func TestPlatformSinkFailsWhenTheDestinationWillNotOpen(t *testing.T) {
	platform := newFakePlatformSink()
	platform.openErr = errors.New("no space")
	sink, err := NewPlatformSink(platform)
	require.NoError(t, err)

	written, err := sink.Write("offer", 0, "x.bin", 5, strings.NewReader("data"), 9)
	require.Error(t, err)
	assert.Equal(t, int64(5), written, "the offset already staged survives a failed reopen")
}

func TestPlatformSinkReportsWhatLandedWhenTheCloseFails(t *testing.T) {
	platform := newFakePlatformSink()
	sink, err := NewPlatformSink(platform)
	require.NoError(t, err)

	// A destination that accepts every chunk but fails to flush has to report the
	// bytes that did land, or a resume would restart from the wrong offset.
	platform.closeErr = errors.New("flush failed")

	written, err := sink.Write("offer", 0, "x.bin", 0, strings.NewReader("netbird"), 7)
	require.Error(t, err)
	assert.Equal(t, int64(7), written)
}

func TestPlatformSinkRejectsNegativeOffset(t *testing.T) {
	sink, err := NewPlatformSink(newFakePlatformSink())
	require.NoError(t, err)

	_, err = sink.Write("offer", 0, "x.bin", -1, strings.NewReader("data"), 4)
	require.Error(t, err)
}

func TestPlatformSinkDeliverSplitsTheReportedDestinations(t *testing.T) {
	platform := newFakePlatformSink()
	platform.delivered = "content://media/1\ncontent://media/2"
	sink, err := NewPlatformSink(platform)
	require.NoError(t, err)

	delivered, err := sink.Deliver(Offer{ID: "offer"}, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"content://media/1", "content://media/2"}, delivered)
}

func TestPlatformSinkDeliverWithoutDestinationsIsEmpty(t *testing.T) {
	sink, err := NewPlatformSink(newFakePlatformSink())
	require.NoError(t, err)

	delivered, err := sink.Deliver(Offer{ID: "offer"}, "")
	require.NoError(t, err)
	assert.Empty(t, delivered, "a text-only offer delivers nothing, rather than one empty path")
}

func TestPlatformSinkCleanupPassesWholeSeconds(t *testing.T) {
	platform := newFakePlatformSink()
	sink, err := NewPlatformSink(platform)
	require.NoError(t, err)

	sink.Cleanup(90*time.Minute, time.Now())
	assert.Equal(t, []int64{5400}, platform.cleanups)
}

func TestNewPlatformSinkRequiresAPlatform(t *testing.T) {
	_, err := NewPlatformSink(nil)
	require.Error(t, err)
}

func TestManagerReportsThePlatformDestinationLabel(t *testing.T) {
	platform := newFakePlatformSink()
	platform.label = "Download/NetBird"
	sink, err := NewPlatformSink(platform)
	require.NoError(t, err)

	mgr, err := NewManager(ManagerConfig{
		Profile: testProfile,
		DataDir: t.TempDir(),
		Sink:    sink,
	})
	require.NoError(t, err)

	require.NoError(t, mgr.SetDestinationDir("/data/data/io.netbird.client/files"))
	assert.Equal(t, "Download/NetBird", mgr.DestinationDir(),
		"the platform's own name for the destination wins over the stored path")
}
