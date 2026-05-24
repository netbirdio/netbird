//go:build !js && !ios && !android

package server

import (
	"image"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/require"
)

// TestTileIsUniformRejectsOutOfRange covers the bounds-check guard added to
// tileIsUniform. Each case below would, before the guard, have produced an
// unsafe.Pointer dereference past the end of img.Pix; the function must now
// return (0,false) and not panic.
func TestTileIsUniformRejectsOutOfRange(t *testing.T) {
	img := makeUniformImage(64, 64, 0x11, 0x22, 0x33)
	cases := []struct {
		name       string
		x, y, w, h int
	}{
		{"negative_x", -1, 0, 8, 8},
		{"negative_y", 0, -1, 8, 8},
		{"x_past_right_edge", 60, 0, 8, 8},
		{"y_past_bottom_edge", 0, 60, 8, 8},
		{"w_overflows_into_oob", 0, 0, 65, 8},
		{"h_overflows_into_oob", 0, 0, 8, 65},
		{"zero_width", 0, 0, 0, 8},
		{"zero_height", 0, 0, 8, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("tileIsUniform panicked: %v", r)
				}
			}()
			pixel, uniform := tileIsUniform(img, tc.x, tc.y, tc.w, tc.h)
			if uniform {
				t.Fatalf("expected uniform=false on out-of-range, got pixel=%#x", pixel)
			}
		})
	}
}

func TestTileIsUniformInRangeStillWorks(t *testing.T) {
	img := makeUniformImage(64, 64, 0x12, 0x34, 0x56)
	pixel, uniform := tileIsUniform(img, 8, 8, 16, 16)
	if !uniform {
		t.Fatal("expected uniform=true for uniformly-painted rect")
	}
	// Pixel is BGRA-shifted internally; just confirm it is non-zero so we
	// know the deref ran.
	if pixel == 0 {
		t.Fatal("expected non-zero packed pixel")
	}
}

// TestSampledColorCountIntoRejectsOutOfRange mirrors the bounds-check guard
// added to sampledColorCountInto: any out-of-range rect must yield 0 with
// no panic and no map mutation that would propagate stale colors.
func TestSampledColorCountIntoRejectsOutOfRange(t *testing.T) {
	img := makeUniformImage(64, 64, 0x11, 0x22, 0x33)
	seen := make(map[uint32]struct{}, 16)
	cases := []struct {
		name       string
		x, y, w, h int
	}{
		{"negative_x", -1, 0, 8, 8},
		{"negative_y", 0, -1, 8, 8},
		{"x_past_right_edge", 60, 0, 8, 8},
		{"y_past_bottom_edge", 0, 60, 8, 8},
		{"w_overflows_into_oob", 0, 0, 65, 8},
		{"h_overflows_into_oob", 0, 0, 8, 65},
		{"zero_dims", 0, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("sampledColorCountInto panicked: %v", r)
				}
			}()
			n := sampledColorCountInto(seen, img, tc.x, tc.y, tc.w, tc.h, 256)
			if n != 0 {
				t.Fatalf("expected 0 colors on out-of-range rect, got %d", n)
			}
		})
	}
}

// TestAppendTightLengthClampsInsteadOfPanicking ensures the function no
// longer panics on out-of-range input: a panic would tear down the entire
// VNC server when the encoder hits an unexpected length.
func TestAppendTightLengthClampsInsteadOfPanicking(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("appendTightLength panicked: %v", r)
		}
	}()
	_ = appendTightLength(nil, -1)
	_ = appendTightLength(nil, tightMaxLength+1)
	_ = appendTightLength(nil, 1<<30)
}

// TestEncodeCursorPseudoRectCapsDimensions ensures the cursor encoder
// refuses unreasonably large sprites: a bad platform-API response with
// w*h*4 that overflows int would otherwise produce an undersized buf and
// a heap overflow on the subsequent copy.
func TestEncodeCursorPseudoRectCapsDimensions(t *testing.T) {
	t.Run("oversized_rejected", func(t *testing.T) {
		img := image.NewRGBA(image.Rect(0, 0, maxCursorDim+1, 1))
		if buf := encodeCursorPseudoRect(img, 0, 0); buf != nil {
			t.Fatalf("expected nil for oversized cursor, got %d bytes", len(buf))
		}
	})
	t.Run("nil_rejected", func(t *testing.T) {
		if buf := encodeCursorPseudoRect(nil, 0, 0); buf != nil {
			t.Fatal("expected nil for nil image")
		}
	})
	t.Run("zero_dims_rejected", func(t *testing.T) {
		img := image.NewRGBA(image.Rect(0, 0, 0, 0))
		if buf := encodeCursorPseudoRect(img, 0, 0); buf != nil {
			t.Fatal("expected nil for zero-dim image")
		}
	})
	t.Run("small_cursor_still_encodes", func(t *testing.T) {
		img := image.NewRGBA(image.Rect(0, 0, 16, 16))
		// Paint a quasi-opaque sprite so the mask path runs.
		for i := range img.Pix {
			img.Pix[i] = 0x80
		}
		buf := encodeCursorPseudoRect(img, 1, 2)
		if buf == nil {
			t.Fatal("expected encoded cursor, got nil")
		}
		// 12-byte rect header + w*h*4 pixels + ((w+7)/8)*h mask bytes.
		want := 12 + 16*16*4 + ((16+7)/8)*16
		if len(buf) != want {
			t.Fatalf("cursor rect length: got %d want %d", len(buf), want)
		}
	})
}

// TestEncodeCursorPseudoRectAtMaxDim sanity-checks the boundary: the cap
// must allow exactly maxCursorDim×maxCursorDim through.
func TestEncodeCursorPseudoRectAtMaxDim(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, maxCursorDim, maxCursorDim))
	if buf := encodeCursorPseudoRect(img, 0, 0); buf == nil {
		t.Fatal("expected non-nil for max-dim cursor (boundary)")
	}
}

// TestCopyRectFindTileRejectsOutOfRangeSrc covers the additional source-
// position guard added to findTileMatch. A scenario where the source
// position recorded in prevTiles is now outside the (possibly shrunken)
// current framebuffer must produce no match: otherwise the encoder would
// emit a CopyRect telling the client to copy from undefined pixels.
func TestCopyRectFindTileRejectsOutOfRangeSrc(t *testing.T) {
	const ts = 64
	const w, h = 128, 128
	cur := image.NewRGBA(image.Rect(0, 0, w, h))
	fillTile(cur, 0, 0, ts, 0x11, 0x22, 0x33)

	d := newCopyRectDetector(ts)
	// Pre-populate prevTiles with a stale source position that falls
	// outside the current framebuffer; this mirrors what would happen
	// after a resize. We compute the same hash the detector would use
	// for the tile at (0,0) of cur and bind that hash to an out-of-range
	// source.
	hash := d.hashTile(cur, 0, 0)
	d.cols = w / ts
	d.tileHash = make([]uint64, (w/ts)*(h/ts))
	d.prevTiles = map[uint64][2]int{
		hash: {w + ts, h + ts}, // out of range
	}

	sx, sy, ok := d.findTileMatch(cur, 0, 0)
	if ok {
		t.Fatalf("expected no match for out-of-range source, got (%d,%d)", sx, sy)
	}
}

// TestBuildVNCNoisePrologueDeterministic locks in the format both sides
// MUST agree on. Drift here breaks every VNC handshake silently (with
// just an "authentication failed" error), so any future refactor that
// changes this output needs to bump the prologue magic and ship a
// migration.
func TestBuildVNCNoisePrologueDeterministic(t *testing.T) {
	a := BuildVNCNoisePrologue(ModeAttach, "")
	b := BuildVNCNoisePrologue(ModeAttach, "")
	if string(a) != string(b) {
		t.Fatalf("non-deterministic prologue: %x vs %x", a, b)
	}

	// Different mode must produce a distinct prologue.
	if string(a) == string(BuildVNCNoisePrologue(ModeSession, "")) {
		t.Fatal("mode change must change prologue")
	}
	// Different username must produce a distinct prologue.
	if string(a) == string(BuildVNCNoisePrologue(ModeAttach, "alice")) {
		t.Fatal("username change must change prologue")
	}
	// Magic prefix must be present so a missing/short prologue (e.g.
	// an old client that wasn't recompiled) fails closed.
	if !strings.HasPrefix(string(a), "NetBird/VNC/Noise/v1") {
		t.Fatalf("prologue missing magic prefix: %q", a)
	}
}

// TestNoise_ClientLiesAboutMode_HandshakeFails proves the prologue
// binding catches a client that writes one mode in the cleartext header
// prefix and then tries to mint a Noise handshake claiming a different
// mode. Without binding, an attacker could declare mode=attach (loose
// OS-user check) while the Noise hash committed to mode=session,
// pretending to be a session user when the server's policy gate ran on
// the attach path.
func TestNoise_ClientLiesAboutMode_HandshakeFails(t *testing.T) {
	addr, srv, serverPub := noiseTestServer(t)
	clientKey := registerSessionKey(t, srv, "alice@example")

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	// Cleartext header says session, but Noise prologue commits to
	// attach. Server reads the cleartext, computes a prologue with
	// session, and the AEAD MAC over the handshake state fails.
	writeHeaderPrefixWithUser(t, conn, ModeSession, "alice")

	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   vncNoiseSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      BuildVNCNoisePrologue(ModeAttach, "alice"),
		StaticKeypair: clientKey,
		PeerStatic:    serverPub,
	})
	require.NoError(t, err)
	msg1, _, _, err := state.WriteMessage(nil, nil)
	require.NoError(t, err)
	_, err = conn.Write(append([]byte("NBV3"), msg1...))
	require.NoError(t, err)

	// Server must reject the connection: either by failing the read
	// of msg2 (the connection is closed) or by sending an RFB failure.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	msg2 := make([]byte, noiseResponderMsgLen)
	if _, err := readFullOrEOF(conn, msg2); err == nil {
		// If the server did write something, it must not be a valid
		// Noise msg2: ReadMessage must fail.
		_, _, _, derr := state.ReadMessage(nil, msg2)
		if derr == nil {
			t.Fatal("expected Noise read to fail when client lies about mode")
		}
	}
}

// TestNoise_ClientLiesAboutUsername_HandshakeFails mirrors the mode
// check above for the username field, which is the other piece of
// cleartext header the prologue binds to.
func TestNoise_ClientLiesAboutUsername_HandshakeFails(t *testing.T) {
	addr, srv, serverPub := noiseTestServer(t)
	clientKey := registerSessionKey(t, srv, "alice@example")

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	writeHeaderPrefixWithUser(t, conn, ModeSession, "alice")

	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   vncNoiseSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      BuildVNCNoisePrologue(ModeSession, "bob"), // lies
		StaticKeypair: clientKey,
		PeerStatic:    serverPub,
	})
	require.NoError(t, err)
	msg1, _, _, err := state.WriteMessage(nil, nil)
	require.NoError(t, err)
	_, err = conn.Write(append([]byte("NBV3"), msg1...))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	msg2 := make([]byte, noiseResponderMsgLen)
	if _, err := readFullOrEOF(conn, msg2); err == nil {
		_, _, _, derr := state.ReadMessage(nil, msg2)
		if derr == nil {
			t.Fatal("expected Noise read to fail when client lies about username")
		}
	}
}

// readFullOrEOF returns nil if buf was fully populated, or an error if
// the connection closed first. Used by the binding tests to tolerate
// the server's two valid failure modes (close vs RFB failure).
func readFullOrEOF(conn net.Conn, buf []byte) (int, error) {
	n, err := conn.Read(buf)
	for n < len(buf) && err == nil {
		var k int
		k, err = conn.Read(buf[n:])
		n += k
	}
	return n, err
}

// TestRegisterConnAuth_RaceWithRevocation covers the TOCTOU race the
// fix in registerConnAuth closes. Without the re-check, a concurrent
// UpdateVNCAuth that removes the client's pubkey AFTER authorizeSession
// runs but BEFORE registerConnAuth inserts into connAuth would leave an
// unauthorized session running until the next policy push.
func TestRegisterConnAuth_RaceWithRevocation(t *testing.T) {
	_, srv, _ := noiseTestServer(t)
	clientKey := registerSessionKey(t, srv, "alice@example")

	header := &connectionHeader{
		identityVerified: true,
		clientStatic:     clientKey.Public,
		mode:             ModeAttach,
	}

	// Authoritative simulation of the race: first registerConnAuth
	// succeeds (caller is in policy), then policy is updated to remove
	// the caller's pubkey, then a fresh registration attempt must be
	// refused even though the original authorizeSession path already
	// said ok=true.
	conn1, conn2 := net.Pipe()
	defer conn1.Close()
	defer conn2.Close()
	require.NoError(t, srv.registerConnAuth(conn1, header))

	// Revoke: empty pubkey list, nobody is authorized anymore.
	srv.UpdateVNCAuth(nil)

	conn3, conn4 := net.Pipe()
	defer conn3.Close()
	defer conn4.Close()
	err := srv.registerConnAuth(conn3, header)
	if err == nil {
		t.Fatal("expected registerConnAuth to refuse after revocation, got nil")
	}
	if !strings.Contains(err.Error(), "authorization revoked") {
		t.Fatalf("unexpected error from post-revocation register: %v", err)
	}
}

// TestEncoderPanicRecovery ensures processFBRequestSafe catches a panic
// from the encode path and surfaces it as an error rather than tearing
// down every session.
func TestEncoderPanicRecovery(t *testing.T) {
	// A session whose encMu is nil-safe-enough that processFBRequest can
	// be called and induce a deterministic panic at one of its earliest
	// dereferences. We only need the recover wrapper to engage.
	s := &session{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("processFBRequestSafe leaked a panic: %v", r)
		}
	}()
	err := s.processFBRequestSafe(fbRequest{})
	if err == nil {
		t.Fatal("expected an error from the recovered panic, got nil")
	}
	if !strings.Contains(err.Error(), "encoder panic") {
		t.Fatalf("error should mention encoder panic, got: %v", err)
	}
}
