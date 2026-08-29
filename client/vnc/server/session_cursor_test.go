//go:build !js && !ios && !android

package server

import (
	"image"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubCursorSource returns a scripted sequence of cursors, standing in for a
// platform cursor source.
type stubCursorSource struct {
	img    *image.RGBA
	serial uint64
}

func (s *stubCursorSource) Width() int  { return 64 }
func (s *stubCursorSource) Height() int { return 64 }

func (s *stubCursorSource) Capture() (*image.RGBA, error) {
	return image.NewRGBA(image.Rect(0, 0, 64, 64)), nil
}

func (s *stubCursorSource) Cursor() (*image.RGBA, int, int, uint64, error) {
	return s.img, 0, 0, s.serial, nil
}

func newCursorSession(src *stubCursorSource) *session {
	return &session{
		capturer:             src,
		clientSupportsCursor: true,
		log:                  log.WithField("test", "cursor"),
	}
}

// X11 passes through the XFixes cursor-serial, which names the cursor rather
// than counting upwards: going back to a cursor shown earlier reports a lower
// value. An ordering comparison discarded that update and left the client stuck
// on whichever cursor had the highest serial, in practice the I-beam.
func TestPendingCursorRect_SwitchingBackToALowerSerial(t *testing.T) {
	sprite := image.NewRGBA(image.Rect(0, 0, 16, 16))
	src := &stubCursorSource{img: sprite, serial: 100}
	s := newCursorSession(src)

	// The arrow, then an I-beam the X server happens to number higher.
	require.NotNil(t, s.pendingCursorRect(), "first cursor must be sent")
	src.serial = 250
	require.NotNil(t, s.pendingCursorRect(), "a different cursor must be sent")

	// Back to the arrow: a lower serial, and still a real change.
	src.serial = 100
	assert.NotNil(t, s.pendingCursorRect(), "returning to an earlier cursor must be sent, not dropped as stale")
}

// An unchanged serial is still the one case that must not produce a rect,
// otherwise every framebuffer update would carry a redundant cursor.
func TestPendingCursorRect_UnchangedSerialIsSkipped(t *testing.T) {
	sprite := image.NewRGBA(image.Rect(0, 0, 16, 16))
	src := &stubCursorSource{img: sprite, serial: 7}
	s := newCursorSession(src)

	require.NotNil(t, s.pendingCursorRect())
	assert.Nil(t, s.pendingCursorRect(), "the same cursor must not be re-sent")
}
