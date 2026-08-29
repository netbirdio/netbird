//go:build !js && !ios && !android

package server

import (
	"image"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCursorCapturer plays back a scripted sequence of cursor sprites, each
// with the serial its platform would report.
type fakeCursorCapturer struct {
	sprites []fakeSprite
	next    int
}

type fakeSprite struct {
	serial uint64
	err    error
}

func (f *fakeCursorCapturer) Width() int  { return 100 }
func (f *fakeCursorCapturer) Height() int { return 100 }

func (f *fakeCursorCapturer) Capture() (*image.RGBA, error) {
	return image.NewRGBA(image.Rect(0, 0, 100, 100)), nil
}

func (f *fakeCursorCapturer) Cursor() (*image.RGBA, int, int, uint64, error) {
	s := f.sprites[min(f.next, len(f.sprites)-1)]
	f.next++
	if s.err != nil {
		return nil, 0, 0, 0, s.err
	}
	return image.NewRGBA(image.Rect(0, 0, 16, 16)), 0, 0, s.serial, nil
}

func newCursorSession(t *testing.T, cap ScreenCapturer) *session {
	t.Helper()
	return &session{
		capturer:             cap,
		clientSupportsCursor: true,
		log:                  log.WithField("test", t.Name()),
	}
}

// X11 reports the XFixes cursor-serial, which names the cursor rather than
// counting upwards: switching back to a cursor shown earlier yields a lower
// value. Ordering the serials treated that as stale and left the client stuck
// on whichever cursor had the highest one, typically the I-beam.
func TestPendingCursorRect_SerialGoingBackwardsStillUpdates(t *testing.T) {
	cap := &fakeCursorCapturer{sprites: []fakeSprite{
		{serial: 100}, // arrow
		{serial: 250}, // I-beam over a text field
		{serial: 100}, // back to the arrow
	}}
	s := newCursorSession(t, cap)

	require.NotNil(t, s.pendingCursorRect(), "the first cursor must be sent")
	assert.Equal(t, uint64(100), s.lastCursorSerial)

	require.NotNil(t, s.pendingCursorRect(), "a different cursor must be sent")
	assert.Equal(t, uint64(250), s.lastCursorSerial)

	require.NotNil(t, s.pendingCursorRect(), "returning to an earlier cursor must be sent too")
	assert.Equal(t, uint64(100), s.lastCursorSerial)
}

// The same serial twice in a row is the same cursor and carries no update.
func TestPendingCursorRect_UnchangedSerialIsSkipped(t *testing.T) {
	cap := &fakeCursorCapturer{sprites: []fakeSprite{{serial: 7}, {serial: 7}}}
	s := newCursorSession(t, cap)

	require.NotNil(t, s.pendingCursorRect())
	assert.Nil(t, s.pendingCursorRect(), "an unchanged serial must not re-send the sprite")
}
