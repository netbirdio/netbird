//go:build ios

package NetBirdSDK

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/netbirdio/netbird/client/internal/filedrop"
)

// FileDropPayloads collects the items of one outgoing transfer.
type FileDropPayloads struct {
	items []filedrop.Payload
}

// NewFileDropPayloads returns an empty payload list to fill before sending.
func NewFileDropPayloads() *FileDropPayloads {
	return &FileDropPayloads{}
}

// AddFile appends a file item backed by a filesystem path the extension can read.
func (p *FileDropPayloads) AddFile(name string, size int64, contentType, path string) error {
	if name == "" {
		return errors.New("file name is required")
	}
	if path == "" {
		return fmt.Errorf("file %s has no path", name)
	}

	p.items = append(p.items, filedrop.Payload{
		Meta: filedrop.FileMeta{
			Name:        name,
			Size:        size,
			ContentType: contentType,
		},
		Open: func(offset int64) (io.ReadCloser, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			if offset > 0 {
				if _, err := f.Seek(offset, io.SeekStart); err != nil {
					_ = f.Close()
					return nil, err
				}
			}
			return f, nil
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
