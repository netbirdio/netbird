//go:build android

package android

import (
	"fmt"

	"github.com/netbirdio/netbird/client/internal/filedrop"
)

// FileDropSink stages incoming payloads on the platform's behalf. Android
// cannot address the user's shared storage by path, so the writing itself
// happens in Java and the engine only drives it.
//
// The methods mirror filedrop.PlatformSink; see that interface for the contract.
type FileDropSink interface {
	// DestinationLabel names where payloads land, for the UI to show in place of
	// a path the platform does not have.
	DestinationLabel() string
	Prepare(offerID string) error
	Received(offerID string, index int) (int64, error)
	OpenWriter(offerID string, index int, name string, offset int64, size int64) (FileDropWriter, error)
	Deliver(offerID string) (string, error)
	Remove(offerID string)
	Cleanup(maxAgeSeconds int64)
}

// FileDropWriter is one payload's destination, opened by a FileDropSink.
//
// WriteChunk takes the bytes rather than filling a caller-supplied buffer, and
// the total is read back through Written: gomobile copies a []byte argument
// into a fresh Java array and never carries a written count back out.
type FileDropWriter interface {
	WriteChunk(p []byte) error
	Close() error
	Written() int64
}

// platformSinkAdapter bridges the gomobile-bound FileDropSink onto the
// interface the engine consumes. The two differ only in the writer type, which
// gomobile cannot share between packages.
type platformSinkAdapter struct {
	sink FileDropSink
}

func newPlatformSinkAdapter(sink FileDropSink) filedrop.PlatformSink {
	return &platformSinkAdapter{sink: sink}
}

func (a *platformSinkAdapter) DestinationLabel() string {
	return a.sink.DestinationLabel()
}

func (a *platformSinkAdapter) Prepare(offerID string) error {
	return a.sink.Prepare(offerID)
}

func (a *platformSinkAdapter) Received(offerID string, index int) (int64, error) {
	return a.sink.Received(offerID, index)
}

func (a *platformSinkAdapter) OpenWriter(offerID string, index int, name string, offset int64, size int64) (filedrop.PlatformWriter, error) {
	w, err := a.sink.OpenWriter(offerID, index, name, offset, size)
	if err != nil {
		return nil, err
	}
	if w == nil {
		return nil, fmt.Errorf("no destination for %s item %d", offerID, index)
	}
	return w, nil
}

func (a *platformSinkAdapter) Deliver(offerID string) (string, error) {
	return a.sink.Deliver(offerID)
}

func (a *platformSinkAdapter) Remove(offerID string) {
	a.sink.Remove(offerID)
}

func (a *platformSinkAdapter) Cleanup(maxAgeSeconds int64) {
	a.sink.Cleanup(maxAgeSeconds)
}
