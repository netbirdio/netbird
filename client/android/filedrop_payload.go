//go:build android

package android

import (
	"errors"
	"fmt"
	"io"

	"github.com/netbirdio/netbird/client/internal/filedrop"
)

// FileSource opens the bytes of one outgoing item. Android hands out content URIs
// rather than paths, so the platform layer owns opening and seeking.
type FileSource interface {
	// Open returns a stream positioned at offset. It is called once per attempt,
	// and again from the start when a transfer resumes.
	Open(offset int64) (SourceStream, error)
}

// SourceStream is the readable half of a FileSource.
//
// It returns each chunk instead of filling a caller-supplied buffer: gomobile
// copies a []byte argument into a fresh Java array and never copies it back, so
// a fill-my-buffer method would hand back the right length with no data. Only
// the return value crosses the bridge intact.
type SourceStream interface {
	// NextChunk returns up to max bytes. An empty result means end of stream.
	NextChunk(max int) ([]byte, error)
	Close() error
}

type sourceStreamReader struct {
	stream SourceStream
	buf    []byte
	eof    bool
}

// FileDropPayloads collects the items of one outgoing transfer.
type FileDropPayloads struct {
	items []filedrop.Payload
}

// NewFileDropPayloads returns an empty payload list to fill before sending.
func NewFileDropPayloads() *FileDropPayloads {
	return &FileDropPayloads{}
}

// AddFile appends a file item backed by a platform-provided source.
func (p *FileDropPayloads) AddFile(name string, size int64, contentType string, source FileSource) error {
	if name == "" {
		return errors.New("file name is required")
	}
	if source == nil {
		return fmt.Errorf("file %s has no source", name)
	}

	p.items = append(p.items, filedrop.Payload{
		Meta: filedrop.FileMeta{
			Name:        name,
			Size:        size,
			ContentType: contentType,
		},
		Open: func(offset int64) (io.ReadCloser, error) {
			stream, err := source.Open(offset)
			if err != nil {
				return nil, err
			}
			if stream == nil {
				return nil, fmt.Errorf("no stream for %s", name)
			}
			return &sourceStreamReader{stream: stream}, nil
		},
	})
	return nil
}

// AddText appends an inline text item.
func (p *FileDropPayloads) AddText(name, text string) error {
	if len(text) > filedrop.MaxInlineTextSize {
		return fmt.Errorf("text exceeds %d bytes", filedrop.MaxInlineTextSize)
	}
	if name == "" {
		name = "text"
	}
	p.items = append(p.items, filedrop.TextPayload(name, text))
	return nil
}

// Length returns the number of items.
func (p *FileDropPayloads) Length() int {
	return len(p.items)
}

func (r *sourceStreamReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for len(r.buf) == 0 {
		if r.eof {
			return 0, io.EOF
		}
		chunk, err := r.stream.NextChunk(len(p))
		if err != nil {
			return 0, err
		}
		if len(chunk) == 0 {
			r.eof = true
			return 0, io.EOF
		}
		r.buf = chunk
	}

	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *sourceStreamReader) Close() error {
	return r.stream.Close()
}
