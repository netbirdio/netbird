package syncstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util"
)

// syncResponseFileName is the name of the file the sync response is serialized
// to, placed inside the configured directory (the state directory).
const syncResponseFileName = "networkmap.pb"

// diskStore serializes the latest sync response to a file on disk instead of
// keeping it in memory. This trades disk I/O for a much smaller memory
// footprint, which matters on memory-constrained platforms (iOS).
type diskStore struct {
	mu   sync.Mutex
	path string
}

// NewDiskStore returns a Store that serializes the sync response to a file in
// the given directory. If dir is empty it falls back to the OS temp directory.
//
// Any file left over from a previous run is removed on construction so a fresh
// store never reads stale data (e.g. another profile's network map).
func NewDiskStore(dir string) Store {
	if dir == "" {
		dir = os.TempDir()
	}
	s := &diskStore{
		path: filepath.Join(dir, syncResponseFileName),
	}
	if err := s.Clear(); err != nil {
		log.Warnf("failed to clear stale sync response file: %v", err)
	}
	return s
}

func (s *diskStore) Set(resp *mgmProto.SyncResponse) error {
	if resp == nil {
		return s.Clear()
	}

	bs, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal sync response: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := util.WriteBytesWithRestrictedPermission(context.Background(), s.path, bs); err != nil {
		return fmt.Errorf("write sync response to %s: %w", s.path, err)
	}

	log.Debugf("sync response persisted to %s (%d bytes)", s.path, len(bs))
	return nil
}

func (s *diskStore) Get() (*mgmProto.SyncResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bs, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			//nolint:nilnil // nil,nil means "nothing stored", per the Store contract; preserve the original behaviour
			return nil, nil
		}
		return nil, fmt.Errorf("read sync response from %s: %w", s.path, err)
	}

	resp := &mgmProto.SyncResponse{}
	if err := proto.Unmarshal(bs, resp); err != nil {
		return nil, fmt.Errorf("unmarshal sync response: %w", err)
	}

	log.Debugf("retrieving latest sync response from %s (%d bytes)", s.path, len(bs))
	return resp, nil
}

func (s *diskStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove sync response file %s: %w", s.path, err)
	}
	return nil
}
