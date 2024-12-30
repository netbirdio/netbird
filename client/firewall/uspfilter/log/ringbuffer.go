package log

import "sync"

// ringBuffer is a simple ring buffer implementation
type ringBuffer struct {
	buf  []byte
	size int
	r, w int64 // Read and write positions
	mu   sync.Mutex
}

func newRingBuffer(size int) *ringBuffer {
	return &ringBuffer{
		buf:  make([]byte, size),
		size: size,
	}
}

func (r *ringBuffer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(p) > r.size {
		p = p[:r.size]
	}

	n = len(p)

	// Write data, handling wrap-around
	pos := int(r.w % int64(r.size))
	writeLen := min(len(p), r.size-pos)
	copy(r.buf[pos:], p[:writeLen])

	// If we have more data and need to wrap around
	if writeLen < len(p) {
		copy(r.buf, p[writeLen:])
	}

	// Update write position
	r.w += int64(n)

	return n, nil
}

func (r *ringBuffer) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.w == r.r {
		return 0, nil
	}

	// Calculate available data accounting for wraparound
	available := int(r.w - r.r)
	if available < 0 {
		available += r.size
	}
	available = min(available, r.size)

	// Limit read to buffer size
	toRead := min(available, len(p))
	if toRead == 0 {
		return 0, nil
	}

	// Read data, handling wrap-around
	pos := int(r.r % int64(r.size))
	readLen := min(toRead, r.size-pos)
	n = copy(p, r.buf[pos:pos+readLen])

	// If we need more data and need to wrap around
	if readLen < toRead {
		n += copy(p[readLen:toRead], r.buf[:toRead-readLen])
	}

	// Update read position
	r.r += int64(n)

	return n, nil
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
