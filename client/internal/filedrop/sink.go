package filedrop

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Sink stages incoming payloads until an offer completes. The receiver writes
// every payload through it and never touches the filesystem directly, so a
// platform whose destination is not a filesystem path can implement its own.
type Sink interface {
	Prepare(id OfferID) error
	Received(id OfferID, index int) (int64, error)
	Write(id OfferID, index int, name string, offset int64, r io.Reader, limit int64) (int64, error)
	Deliver(offer Offer, destDir string) ([]string, error)
	Remove(id OfferID)
	Cleanup(maxAge time.Duration, now time.Time)
}

// PlatformSink is the platform-facing half of a Sink, bound over gomobile. It
// carries the same calls with only types gomobile can bind, so a platform can
// stage payloads somewhere the engine cannot address by path, such as an
// Android MediaStore entry.
type PlatformSink interface {
	// DestinationLabel names where payloads land, for the UI to show in place of
	// a path the platform does not have.
	DestinationLabel() string
	Prepare(offerID string) error
	Received(offerID string, index int) (int64, error)
	OpenWriter(offerID string, index int, name string, offset int64, size int64) (PlatformWriter, error)
	// Deliver publishes an offer's payloads and returns where each one landed,
	// newline-separated, in the order the offer announced them, text payloads
	// skipped.
	Deliver(offerID string) (string, error)
	Remove(offerID string)
	Cleanup(maxAgeSeconds int64)
}

// PlatformWriter is one payload's destination, opened by a PlatformSink.
//
// WriteChunk takes the bytes by value rather than filling a caller-supplied
// buffer: gomobile copies a []byte argument into a fresh Java array, which is
// the right direction here, but the written count never crosses back, so the
// writer reports its own total through Written instead, read after Close.
type PlatformWriter interface {
	WriteChunk(p []byte) error
	Close() error
	Written() int64
}

// platformSink adapts a PlatformSink to the Sink the receiver uses.
type platformSink struct {
	platform PlatformSink
}

// platformWriter adapts a PlatformWriter to io.Writer.
type platformWriter struct {
	w PlatformWriter
}

// NewPlatformSink wraps a platform-provided sink for the receiver to stage into.
func NewPlatformSink(platform PlatformSink) (Sink, error) {
	if platform == nil {
		return nil, fmt.Errorf("platform sink is required")
	}
	return &platformSink{platform: platform}, nil
}

// DestinationLabel reports where the platform delivers payloads.
func (s *platformSink) DestinationLabel() string {
	return s.platform.DestinationLabel()
}

func (s *platformSink) Prepare(id OfferID) error {
	return s.platform.Prepare(string(id))
}

func (s *platformSink) Received(id OfferID, index int) (int64, error) {
	return s.platform.Received(string(id), index)
}

func (s *platformSink) Write(id OfferID, index int, name string, offset int64, r io.Reader, limit int64) (int64, error) {
	if offset < 0 {
		return 0, fmt.Errorf("negative offset %d", offset)
	}

	w, err := s.platform.OpenWriter(string(id), index, name, offset, limit)
	if err != nil {
		return offset, fmt.Errorf("open destination: %w", err)
	}

	_, copyErr := io.Copy(&platformWriter{w: w}, io.LimitReader(r, limit-offset))
	closeErr := w.Close()

	written := w.Written()
	if copyErr != nil {
		return written, fmt.Errorf("write destination: %w", copyErr)
	}
	if closeErr != nil {
		return written, fmt.Errorf("close destination: %w", closeErr)
	}
	return written, nil
}

func (s *platformSink) Deliver(offer Offer, _ string) ([]string, error) {
	delivered, err := s.platform.Deliver(string(offer.ID))
	if err != nil {
		return nil, err
	}
	return splitDelivered(delivered), nil
}

func (s *platformSink) Remove(id OfferID) {
	s.platform.Remove(string(id))
}

func (s *platformSink) Cleanup(maxAge time.Duration, _ time.Time) {
	s.platform.Cleanup(int64(maxAge / time.Second))
}

func (p *platformWriter) Write(b []byte) (int, error) {
	if err := p.w.WriteChunk(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func splitDelivered(delivered string) []string {
	if delivered == "" {
		return nil
	}
	return strings.Split(delivered, "\n")
}
