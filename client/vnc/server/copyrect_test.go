//go:build !js && !ios && !android

package server

import (
	"image"
	"testing"
)

// fillTile paints a tileSize×tileSize block of img at (x,y) with the colour
// derived from (r,g,b) so the test can construct distinct-content tiles.
func fillTile(img *image.RGBA, x, y, ts int, r, g, b byte) {
	for row := 0; row < ts; row++ {
		off := (y+row)*img.Stride + x*4
		for col := 0; col < ts; col++ {
			img.Pix[off+col*4+0] = r
			img.Pix[off+col*4+1] = g
			img.Pix[off+col*4+2] = b
			img.Pix[off+col*4+3] = 0xff
		}
	}
}

// copyTile copies a tileSize×tileSize block from src(sx,sy) to dst(dx,dy).
func copyTile(dst, src *image.RGBA, sx, sy, dx, dy, ts int) {
	for row := 0; row < ts; row++ {
		srcOff := (sy+row)*src.Stride + sx*4
		dstOff := (dy+row)*dst.Stride + dx*4
		copy(dst.Pix[dstOff:dstOff+ts*4], src.Pix[srcOff:srcOff+ts*4])
	}
}

func TestCopyRectDetector_DetectsVerticalScroll(t *testing.T) {
	const w, h = 256, 192 // 4×3 tiles at 64px
	const ts = 64

	prev := image.NewRGBA(image.Rect(0, 0, w, h))
	cur := image.NewRGBA(image.Rect(0, 0, w, h))

	// prev: 12 tiles each with a unique colour.
	for ty := 0; ty < 3; ty++ {
		for tx := 0; tx < 4; tx++ {
			fillTile(prev, tx*ts, ty*ts, ts, byte(tx*40), byte(ty*60), 0x80)
		}
	}
	// cur: simulate a single-tile-row scroll upward, every tile copied from
	// the row below in prev, top row is new content.
	for ty := 0; ty < 2; ty++ {
		for tx := 0; tx < 4; tx++ {
			copyTile(cur, prev, tx*ts, (ty+1)*ts, tx*ts, ty*ts, ts)
		}
	}
	// Bottom row of cur: new colour, not a match.
	for tx := 0; tx < 4; tx++ {
		fillTile(cur, tx*ts, 2*ts, ts, 0xff, 0xff, 0xff)
	}

	d := newCopyRectDetector(ts)
	d.rebuild(prev, w, h)

	tiles := diffTiles(prev, cur, w, h, ts)
	moves, remaining := d.extractCopyRectTiles(cur, tiles)

	// Expect 8 CopyRect moves (top two rows) and 4 residual tiles (bottom row).
	if len(moves) != 8 {
		t.Fatalf("moves: want 8, got %d", len(moves))
	}
	if len(remaining) != 4 {
		t.Fatalf("remaining: want 4, got %d", len(remaining))
	}
	// Spot-check one move: cur (0, 0) should map to prev (0, 64).
	var found bool
	for _, m := range moves {
		if m.dstX == 0 && m.dstY == 0 {
			if m.srcX != 0 || m.srcY != ts {
				t.Fatalf("move at (0,0): src=(%d,%d), want (0,%d)", m.srcX, m.srcY, ts)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no move for dst (0,0)")
	}
}

// rectsOverlap reports whether two ts×ts tiles at the given origins overlap.
func tilesOverlap(ax, ay, bx, by, ts int) bool {
	return ax < bx+ts && bx < ax+ts && ay < by+ts && by < ay+ts
}

// TestCopyRectDetector_DownwardScrollNoOverlap exercises a downward scroll,
// where each move's source is the destination of the move one row above it.
// Emitting all of them in order would corrupt the client framebuffer because
// the earlier move overwrites the source pixels the later move reads. The
// detector must drop any move whose source overlaps a prior move's
// destination and route that tile to pixel encoding instead.
func TestCopyRectDetector_DownwardScrollNoOverlap(t *testing.T) {
	const w, h = 256, 192 // 4×3 tiles at 64px
	const ts = 64

	prev := image.NewRGBA(image.Rect(0, 0, w, h))
	cur := image.NewRGBA(image.Rect(0, 0, w, h))

	// prev: 12 tiles each with a unique colour.
	for ty := 0; ty < 3; ty++ {
		for tx := 0; tx < 4; tx++ {
			fillTile(prev, tx*ts, ty*ts, ts, byte(tx*40), byte(ty*60), 0x80)
		}
	}
	// cur: scroll downward by one row. Rows 1 and 2 are copied from prev
	// rows 0 and 1; the top row is new content.
	for ty := 1; ty < 3; ty++ {
		for tx := 0; tx < 4; tx++ {
			copyTile(cur, prev, tx*ts, (ty-1)*ts, tx*ts, ty*ts, ts)
		}
	}
	for tx := 0; tx < 4; tx++ {
		fillTile(cur, tx*ts, 0, ts, 0xff, 0xff, 0xff)
	}

	d := newCopyRectDetector(ts)
	d.rebuild(prev, w, h)

	tiles := diffTiles(prev, cur, w, h, ts)
	wantTiles := len(tiles)
	moves, remaining := d.extractCopyRectTiles(cur, tiles)

	// No move's source may overlap an earlier move's destination.
	for i, m := range moves {
		for _, prior := range moves[:i] {
			if tilesOverlap(m.srcX, m.srcY, prior.dstX, prior.dstY, ts) {
				t.Fatalf("move %d src (%d,%d) overlaps prior dst (%d,%d)",
					i, m.srcX, m.srcY, prior.dstX, prior.dstY)
			}
		}
	}

	// The dropped row-2 moves must fall through to pixel encoding rather than
	// being silently skipped, so the region still updates correctly.
	if len(moves)+len(remaining) != wantTiles {
		t.Fatalf("moves(%d)+remaining(%d) != dirty tiles(%d): a tile was lost",
			len(moves), len(remaining), wantTiles)
	}
	if len(moves) != 4 {
		t.Fatalf("moves: want 4 (top scrolled row only), got %d", len(moves))
	}
}

func TestCopyRectDetector_RejectsSelfMatch(t *testing.T) {
	const w, h = 128, 128
	const ts = 64

	prev := image.NewRGBA(image.Rect(0, 0, w, h))
	cur := image.NewRGBA(image.Rect(0, 0, w, h))

	// prev: 4 tiles, all unique
	fillTile(prev, 0, 0, ts, 0x10, 0x20, 0x30)
	fillTile(prev, ts, 0, ts, 0x40, 0x50, 0x60)
	fillTile(prev, 0, ts, ts, 0x70, 0x80, 0x90)
	fillTile(prev, ts, ts, ts, 0xa0, 0xb0, 0xc0)

	// cur: tile (0,0) unchanged, others changed but content same as prev's (0,0).
	fillTile(cur, 0, 0, ts, 0x10, 0x20, 0x30) // self-match
	fillTile(cur, ts, 0, ts, 0xff, 0xff, 0xff)
	fillTile(cur, 0, ts, ts, 0xff, 0xff, 0xff)
	fillTile(cur, ts, ts, ts, 0xff, 0xff, 0xff)

	d := newCopyRectDetector(ts)
	d.rebuild(prev, w, h)

	// Tile (0,0) is not in the dirty list (it's unchanged) so it should not
	// produce a move even though its hash matches prev (0,0).
	tiles := diffTiles(prev, cur, w, h, ts)
	moves, _ := d.extractCopyRectTiles(cur, tiles)
	for _, m := range moves {
		if m.dstX == 0 && m.dstY == 0 {
			t.Fatalf("unexpected move at (0,0)")
		}
	}
}

func TestCopyRectDetector_PassThroughWhenNoMatch(t *testing.T) {
	const w, h = 64, 64
	const ts = 64

	prev := image.NewRGBA(image.Rect(0, 0, w, h))
	cur := image.NewRGBA(image.Rect(0, 0, w, h))
	fillTile(prev, 0, 0, ts, 0x11, 0x22, 0x33)
	fillTile(cur, 0, 0, ts, 0xaa, 0xbb, 0xcc) // wholly different

	d := newCopyRectDetector(ts)
	d.rebuild(prev, w, h)
	tiles := diffTiles(prev, cur, w, h, ts)
	moves, remaining := d.extractCopyRectTiles(cur, tiles)

	if len(moves) != 0 {
		t.Fatalf("expected 0 moves, got %d", len(moves))
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 residual tile, got %d", len(remaining))
	}
}

func TestEncodeCopyRectBody_Layout(t *testing.T) {
	got := encodeCopyRectBody(100, 200, 300, 400, 64, 48)
	if len(got) != 16 {
		t.Fatalf("CopyRect body length: want 16, got %d", len(got))
	}
	// Dest position
	if got[0] != 0x01 || got[1] != 0x2c || got[2] != 0x01 || got[3] != 0x90 {
		t.Fatalf("bad dest bytes: % x", got[0:4])
	}
	// Width, height
	if got[4] != 0 || got[5] != 64 || got[6] != 0 || got[7] != 48 {
		t.Fatalf("bad size bytes: % x", got[4:8])
	}
	// Encoding = 1
	if got[11] != 0x01 {
		t.Fatalf("bad encoding byte: 0x%02x", got[11])
	}
	// Source position
	if got[12] != 0 || got[13] != 100 || got[14] != 0 || got[15] != 200 {
		t.Fatalf("bad src bytes: % x", got[12:16])
	}
}
