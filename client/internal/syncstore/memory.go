package syncstore

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// memoryStore keeps the latest sync response in memory.
type memoryStore struct {
	mu     sync.RWMutex
	latest *mgmProto.SyncResponse
}

// NewMemoryStore returns a Store that keeps the sync response in memory.
func NewMemoryStore() Store {
	return &memoryStore{}
}

func (s *memoryStore) Set(resp *mgmProto.SyncResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.latest = resp
	return nil
}

func (s *memoryStore) Get() (*mgmProto.SyncResponse, error) {
	s.mu.RLock()
	latest := s.latest
	s.mu.RUnlock()

	if latest == nil {
		//nolint:nilnil // nil,nil means "nothing stored", per the Store contract; preserve the original behaviour
		return nil, nil
	}

	log.Debugf("retrieving latest sync response with size %d bytes", proto.Size(latest))
	sr, ok := proto.Clone(latest).(*mgmProto.SyncResponse)
	if !ok {
		return nil, fmt.Errorf("clone sync response")
	}
	return sr, nil
}

func (s *memoryStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.latest = nil
	return nil
}
