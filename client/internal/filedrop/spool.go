package filedrop

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

// Spool stages incoming payloads in an app-private directory.
type Spool struct {
	root string
}

// NewSpool prepares the spool directory tree under root.
func NewSpool(root string) (*Spool, error) {
	if root == "" {
		return nil, fmt.Errorf("empty spool root")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create spool root: %w", err)
	}
	return &Spool{root: root}, nil
}

// Root returns the spool base directory.
func (s *Spool) Root() string {
	return s.root
}

// OfferDir returns the directory holding one offer's payloads.
func (s *Spool) OfferDir(id OfferID) string {
	return filepath.Join(s.root, string(id))
}

func (s *Spool) filePath(id OfferID, index int) string {
	return filepath.Join(s.OfferDir(id), strconv.Itoa(index))
}

// Prepare creates the directory for an offer.
func (s *Spool) Prepare(id OfferID) error {
	if err := os.MkdirAll(s.OfferDir(id), 0o700); err != nil {
		return fmt.Errorf("create offer dir: %w", err)
	}
	return nil
}

// Received returns how many bytes of one item are already staged.
func (s *Spool) Received(id OfferID, index int) (int64, error) {
	info, err := os.Stat(s.filePath(id, index))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("stat spool file: %w", err)
	}
	return info.Size(), nil
}

// Write appends the payload at offset, truncating any bytes past it first. The
// announced name plays no part: payloads are staged under their index and only
// take their name in Deliver.
func (s *Spool) Write(id OfferID, index int, _ string, offset int64, r io.Reader, limit int64) (int64, error) {
	if offset < 0 {
		return 0, fmt.Errorf("negative offset %d", offset)
	}

	path := s.filePath(id, index)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("open spool file: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Debugf("close spool file: %v", err)
		}
	}()

	if err := f.Truncate(offset); err != nil {
		return 0, fmt.Errorf("truncate spool file: %w", err)
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek spool file: %w", err)
	}

	written, err := io.Copy(f, io.LimitReader(r, limit-offset))
	if err != nil {
		return offset + written, fmt.Errorf("write spool file: %w", err)
	}
	return offset + written, nil
}

// Deliver moves an offer's staged payloads into destDir under their announced
// names and returns where each one landed.
func (s *Spool) Deliver(offer Offer, destDir string) ([]string, error) {
	return deliver(s, offer, destDir)
}

// Path returns the staged path of one item for the platform layer to deliver from.
func (s *Spool) Path(id OfferID, index int) string {
	return s.filePath(id, index)
}

// Remove deletes an offer's staged payloads.
func (s *Spool) Remove(id OfferID) {
	if err := os.RemoveAll(s.OfferDir(id)); err != nil {
		log.Debugf("remove spool dir: %v", err)
	}
}

// Purge removes every staged payload.
func (s *Spool) Purge() {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		log.Debugf("read spool root: %v", err)
		return
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(s.root, entry.Name())); err != nil {
			log.Debugf("remove spool entry: %v", err)
		}
	}
}

// Cleanup removes offer directories older than maxAge.
func (s *Spool) Cleanup(maxAge time.Duration, now time.Time) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		log.Debugf("read spool root: %v", err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			log.Debugf("stat spool entry: %v", err)
			continue
		}
		if now.Sub(info.ModTime()) < maxAge {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.root, entry.Name())); err != nil {
			log.Debugf("remove stale spool dir: %v", err)
		}
	}
}
