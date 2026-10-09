package statemanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

// store is where a Manager keeps its states between runs.
type store interface {
	// load returns the states persisted by an earlier run, or an empty map
	// when there are none. deleteCorrupt asks the store to move a state it
	// cannot parse out of the way.
	load(deleteCorrupt bool) (map[string]json.RawMessage, error)
	// save replaces the persisted states with data.
	save(ctx context.Context, data []byte) error
}

// fileStore persists states to a file, which is what an installed agent needs:
// it changes routing, DNS and firewall rules on the host, and a later run has
// to know what to put back.
type fileStore struct {
	path string
}

func (f *fileStore) load(deleteCorrupt bool) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Debugf("state file %s does not exist", f.path)
			return nil, nil //nolint:nilnil // no file is not a failure, there is simply nothing to load
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var rawStates map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawStates); err != nil {
		if len(bytes.TrimSpace(data)) == 0 {
			log.Warnf("state file %s is empty (%d bytes)", f.path, len(data))
		} else {
			log.Warnf("state file %s has malformed content (%d bytes)", f.path, len(data))
		}
		f.handleCorrupted(deleteCorrupt)
		return nil, fmt.Errorf("unmarshal states: %w", err)
	}

	return rawStates, nil
}

func (f *fileStore) save(ctx context.Context, data []byte) error {
	return util.WriteBytesWithRestrictedPermission(ctx, f.path, data)
}

// handleCorrupted moves a state file that cannot be parsed aside, so the next
// run starts from nothing rather than failing on the same content forever.
func (f *fileStore) handleCorrupted(deleteCorrupt bool) {
	if !deleteCorrupt {
		return
	}
	log.Warn("State file appears to be corrupted, attempting to back it up")

	backupPath := fmt.Sprintf("%s.corrupted.%d", f.path, time.Now().UnixNano())
	if err := os.Rename(f.path, backupPath); err != nil {
		log.Errorf("Failed to backup corrupted state file: %v", err)
		return
	}

	log.Infof("Created backup of corrupted state file at: %s", backupPath)
}

// memoryStore keeps nothing. An embedded client in netstack mode changes
// nothing on the host, so there is no state a later run has to restore, and
// writing one would mean reading and overwriting another installation's file.
type memoryStore struct{}

func (memoryStore) load(bool) (map[string]json.RawMessage, error) {
	return map[string]json.RawMessage{}, nil
}

func (memoryStore) save(context.Context, []byte) error {
	return nil
}
