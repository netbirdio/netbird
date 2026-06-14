//go:build !js && !ios && !android

package server

import (
	"hash/maphash"
	"image"
)

// copyRectDetector finds tiles in the current frame that match the content
// of some tile-aligned region of the previous frame, so we can emit them as
// CopyRect rectangles (16 wire bytes) instead of re-encoding the pixels.
//
// The detector keeps two structures:
//   - tileHash, a flat slice of one hash per tile-aligned position, used as
//     the source of truth for the previous frame's tile content.
//   - prevTiles, a hash → position lookup used during findTileMatch.
//
// updateDirty rehashes only the tiles that changed this frame, so the
// steady-state cost is proportional to the dirty set, not the framebuffer.
// A full rebuild from scratch is only done on the first frame or when the
// detector has not yet been initialized for the current resolution.
//
// Limitations:
//   - Only tile-aligned source positions are considered. Sub-tile-aligned
//     moves (e.g. window dragged by 7 pixels) are not detected. This still
//     covers the common case of vertical/horizontal scrolling, which always
//     produces tile-aligned matches at the tile granularity.
//   - 64-bit maphash collisions are assumed not to happen. The probability
//     for any single frame's hash universe is ~2^-32 * tileCount² which is
//     vanishingly small at typical resolutions; if we ever observe one we
//     can fall back to a full memcmp verification.
type copyRectDetector struct {
	seed       maphash.Seed
	tileSize   int
	w, h       int
	cols, rows int
	// tileHash[ty*cols + tx] is the current hash of the tile at (tx, ty)
	// in the previous frame. Lookup uses this to detect stale prevTiles
	// entries: incremental updates may leave hash→pos entries pointing
	// at a tile whose content has since changed.
	tileHash []uint64
	// prevTiles maps a tile hash to a (x, y) origin in the previous frame.
	prevTiles map[uint64][2]int
	// hash is reused across hash computations to keep the per-tile lookup
	// path allocation-free.
	hash maphash.Hash
}

func newCopyRectDetector(tileSize int) *copyRectDetector {
	d := &copyRectDetector{
		seed:      maphash.MakeSeed(),
		tileSize:  tileSize,
		prevTiles: make(map[uint64][2]int),
	}
	d.hash.SetSeed(d.seed)
	return d
}

// resize ensures the per-tile tables match the given framebuffer size.
// Called from rebuild before each full hash sweep.
func (d *copyRectDetector) resize(w, h int) {
	if d.w == w && d.h == h && d.tileHash != nil {
		return
	}
	d.w, d.h = w, h
	d.cols = w / d.tileSize
	d.rows = h / d.tileSize
	d.tileHash = make([]uint64, d.cols*d.rows)
}

// hashTile computes the 64-bit maphash of one tile-aligned tile of frame.
func (d *copyRectDetector) hashTile(frame *image.RGBA, tx, ty int) uint64 {
	d.hash.Reset()
	ts := d.tileSize
	stride := frame.Stride
	rowBytes := ts * 4
	base := ty*stride + tx*4
	for row := 0; row < ts; row++ {
		off := base + row*stride
		_, _ = d.hash.Write(frame.Pix[off : off+rowBytes])
	}
	return d.hash.Sum64()
}

// rebuild discards everything and rehashes the whole frame. O(w*h). Use
// for the first frame or after the detector has been resized. Steady-state
// updates should go through updateDirty instead.
func (d *copyRectDetector) rebuild(frame *image.RGBA, w, h int) {
	d.resize(w, h)
	if d.prevTiles == nil {
		d.prevTiles = make(map[uint64][2]int)
	} else {
		clear(d.prevTiles)
	}
	ts := d.tileSize
	for ty := 0; ty+ts <= h; ty += ts {
		for tx := 0; tx+ts <= w; tx += ts {
			sum := d.hashTile(frame, tx, ty)
			d.tileHash[(ty/ts)*d.cols+(tx/ts)] = sum
			if _, exists := d.prevTiles[sum]; !exists {
				d.prevTiles[sum] = [2]int{tx, ty}
			}
		}
	}
}

// updateDirty rehashes only the tiles named in dirty (each entry is
// [x, y, w, h] with w and h equal to tileSize). O(len(dirty)) work, which
// in the common case is a tiny fraction of the whole framebuffer.
//
// The prevTiles map is replaced on collision rather than first-wins so a
// newly-hashed tile claims the slot. Old, stale entries pointing at tiles
// that no longer carry that hash are filtered at lookup time via tileHash.
func (d *copyRectDetector) updateDirty(frame *image.RGBA, w, h int, dirty [][4]int) {
	if d.w != w || d.h != h || d.tileHash == nil {
		d.rebuild(frame, w, h)
		return
	}
	ts := d.tileSize
	for _, r := range dirty {
		if r[2] != ts || r[3] != ts {
			continue
		}
		tx, ty := r[0], r[1]
		if tx+ts > w || ty+ts > h {
			continue
		}
		sum := d.hashTile(frame, tx, ty)
		d.tileHash[(ty/ts)*d.cols+(tx/ts)] = sum
		// Latest-wins on collision: ensures the most recent owner of this
		// hash is the one we'll return on lookup. The previous owner's
		// entry, if any, gets shadowed; if its content has changed it's
		// stale anyway and findTileMatch's verification will skip it.
		d.prevTiles[sum] = [2]int{tx, ty}
	}
}

// findTileMatch hashes the current-frame tile at (dstX, dstY) and looks up
// its hash in the previous-frame map. Returns (srcX, srcY, true) when a
// matching tile-aligned tile exists at a different position whose stored
// hash still equals the requested hash (so the result is not stale).
func (d *copyRectDetector) findTileMatch(cur *image.RGBA, dstX, dstY int) (int, int, bool) {
	if len(d.prevTiles) == 0 || d.tileHash == nil {
		return 0, 0, false
	}
	ts := d.tileSize
	if dstX+ts > cur.Rect.Dx() || dstY+ts > cur.Rect.Dy() {
		return 0, 0, false
	}
	sum := d.hashTile(cur, dstX, dstY)
	pos, ok := d.prevTiles[sum]
	if !ok {
		return 0, 0, false
	}
	if pos[0] == dstX && pos[1] == dstY {
		return 0, 0, false
	}
	// Reject source coords that fall outside the current framebuffer
	// (frame may have shrunk since the source position was recorded). A
	// CopyRect with an out-of-range source would have the client copy
	// from undefined pixels, so drop the match and let the encoder send
	// the rect normally.
	if pos[0] < 0 || pos[1] < 0 || pos[0]+ts > cur.Rect.Dx() || pos[1]+ts > cur.Rect.Dy() {
		return 0, 0, false
	}
	// Reject stale entries: the position the map points at must still
	// carry the same hash according to our per-tile array.
	hashIdx := (pos[1]/ts)*d.cols + pos[0]/ts
	if hashIdx < 0 || hashIdx >= len(d.tileHash) {
		return 0, 0, false
	}
	if d.tileHash[hashIdx] != sum {
		return 0, 0, false
	}
	return pos[0], pos[1], true
}

// extractCopyRectTiles examines the diff-produced (per-tile) dirty list and
// pulls out any tiles whose current-frame content matches a prev-frame tile
// at a different position. Returns the CopyRect candidates and the residual
// dirty tiles that still need pixel encoding.
type copyRectMove struct {
	srcX, srcY int
	dstX, dstY int
}

func (d *copyRectDetector) extractCopyRectTiles(cur *image.RGBA, dirtyTiles [][4]int) (moves []copyRectMove, remaining [][4]int) {
	ts := d.tileSize
	remaining = dirtyTiles[:0:cap(dirtyTiles)]
	for _, r := range dirtyTiles {
		if r[2] == ts && r[3] == ts {
			if sx, sy, ok := d.findTileMatch(cur, r[0], r[1]); ok {
				// The client applies moves sequentially against its live
				// framebuffer. If this move's source overlaps the
				// destination of any move already queued, that destination
				// has overwritten the source pixels client-side, so the
				// copy would read corrupted data. Drop it and let the tile
				// fall through to normal pixel encoding instead.
				if tileOverlapsPriorDst(moves, sx, sy, ts) {
					remaining = append(remaining, r)
					continue
				}
				moves = append(moves, copyRectMove{
					srcX: sx, srcY: sy, dstX: r[0], dstY: r[1],
				})
				continue
			}
		}
		remaining = append(remaining, r)
	}
	return moves, remaining
}

// tileOverlapsPriorDst reports whether the tileSize-square source rectangle
// at (srcX, srcY) intersects the destination rectangle of any move already
// emitted. All move rectangles are ts×ts, so the test reduces to a
// per-axis distance check.
func tileOverlapsPriorDst(moves []copyRectMove, srcX, srcY, ts int) bool {
	for _, m := range moves {
		dx := srcX - m.dstX
		dy := srcY - m.dstY
		if dx > -ts && dx < ts && dy > -ts && dy < ts {
			return true
		}
	}
	return false
}
