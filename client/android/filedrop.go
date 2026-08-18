//go:build android

package android

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/filedrop"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

const filedropDataSubdir = "filedrop"

// FileDrop is the platform-facing handle on one profile's file drop state. It
// outlives the engine: the manager keeps policy and history readable while the
// tunnel is down, and sending simply fails until it comes back up.
type FileDrop struct {
	mu        sync.Mutex
	configDir string
	profileID string
	manager   *filedrop.Manager
	listener  FileDropListener
}

// NewFileDrop opens the file drop state of the given profile.
func NewFileDrop(configDir, profileID string) (*FileDrop, error) {
	if configDir == "" || profileID == "" {
		return nil, errors.New("file drop requires a config dir and profile ID")
	}

	prefs, err := newProfilePrefs(configDir, profileID)
	if err != nil {
		return nil, err
	}

	fd := &FileDrop{configDir: configDir, profileID: profileID}
	manager, err := filedrop.NewManager(filedrop.ManagerConfig{
		Profile: profilemanager.ID(profileID),
		DataDir: filepath.Join(configDir, filedropDataSubdir, profileID),
		Store:   filedrop.NewProfileStore(prefs.prefs),
		Events:  fd.publish,
	})
	if err != nil {
		return nil, fmt.Errorf("create file drop manager: %w", err)
	}

	fd.manager = manager
	return fd, nil
}

// ProfileID returns the profile this handle belongs to.
func (f *FileDrop) ProfileID() string {
	return f.profileID
}

// SetListener installs the event listener, replacing any previous one.
func (f *FileDrop) SetListener(listener FileDropListener) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listener = listener
}

// Listener returns the installed event listener, nil when there is none.
func (f *FileDrop) Listener() FileDropListener {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listener
}

// RemoveListener stops event delivery.
func (f *FileDrop) RemoveListener() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listener = nil
}

// Send starts an asynchronous transfer and returns its local transfer ID.
func (f *FileDrop) Send(peerKey, peerName, peerIP string, payloads *FileDropPayloads) (string, error) {
	if payloads == nil || payloads.Length() == 0 {
		return "", errors.New("nothing to send")
	}

	addr, err := netip.ParseAddr(peerIP)
	if err != nil {
		return "", fmt.Errorf("parse peer address %q: %w", peerIP, err)
	}

	id, err := f.manager.Send(filedrop.PeerKey(peerKey), peerName, addr.Unmap(), payloads.items)
	if err != nil {
		return "", err
	}
	return string(id), nil
}

// Accept releases a pending incoming offer for download.
func (f *FileDrop) Accept(transferID string) error {
	return f.manager.Accept(filedrop.OfferID(transferID))
}

// Decline refuses a pending incoming offer.
func (f *FileDrop) Decline(transferID string) error {
	return f.manager.Decline(filedrop.OfferID(transferID))
}

// Cancel aborts a transfer in either direction.
func (f *FileDrop) Cancel(transferID string) {
	f.manager.Cancel(filedrop.OfferID(transferID))
}

// Transfers returns the history, newest first.
func (f *FileDrop) Transfers() *FileDropTransferArray {
	transfers := f.manager.Transfers()
	items := make([]*FileDropTransfer, 0, len(transfers))
	for _, t := range transfers {
		items = append(items, toFileDropTransfer(t))
	}
	return &FileDropTransferArray{items: items}
}

// Transfer returns one history entry, or nil when it is unknown.
func (f *FileDrop) Transfer(transferID string) *FileDropTransfer {
	for _, t := range f.manager.Transfers() {
		if string(t.ID) == transferID {
			return toFileDropTransfer(t)
		}
	}
	return nil
}

// DeleteTransfer removes one history entry, cancelling it when still live.
func (f *FileDrop) DeleteTransfer(transferID string) {
	f.manager.DeleteTransfer(filedrop.OfferID(transferID))
}

// Mode returns the base receiving mode.
func (f *FileDrop) Mode() int {
	return int(f.manager.Policy().Get().Mode)
}

// SetMode changes the base receiving mode.
func (f *FileDrop) SetMode(mode int) error {
	return f.manager.Policy().SetMode(filedrop.Mode(mode))
}

// DestinationDir returns the directory received files are delivered to.
func (f *FileDrop) DestinationDir() string {
	return f.manager.DestinationDir()
}

// SetDestinationDir persists the delivery directory. It must be a filesystem
// path the app can write; content URIs are not paths, so the platform layer
// moves files out of this directory afterwards.
func (f *FileDrop) SetDestinationDir(dir string) error {
	return f.manager.SetDestinationDir(dir)
}

// PeerRule returns the rule stored for one sender.
func (f *FileDrop) PeerRule(peerKey string) int {
	return int(f.manager.Policy().Get().Senders[filedrop.PeerKey(peerKey)])
}

// SetPeerRule sets or clears the exception for one sender.
func (f *FileDrop) SetPeerRule(peerKey string, rule int) error {
	return f.manager.SetSenderRule(filedrop.PeerKey(peerKey), filedrop.SenderRule(rule))
}

// Close stops the receiver and aborts every outgoing transfer.
func (f *FileDrop) Close() error {
	f.RemoveListener()
	return f.manager.Close()
}

func (f *FileDrop) publish(kind filedrop.EventKind, transfer filedrop.Transfer) {
	f.mu.Lock()
	listener := f.listener
	f.mu.Unlock()
	if listener == nil {
		return
	}
	listener.OnFileDropEvent(int(kind), toFileDropTransfer(transfer))
}

// defaultFileDropDir is the app-private landing directory used until the
// platform layer configures one.
func defaultFileDropDir(configDir, profileID string) string {
	return filepath.Join(configDir, filedropDataSubdir, profileID, "incoming")
}

// ensureFileDropDestination seeds the delivery directory on first use, so a
// received file always has somewhere to land.
func ensureFileDropDestination(fd *FileDrop) {
	if fd.DestinationDir() != "" {
		return
	}
	dir := defaultFileDropDir(fd.configDir, fd.profileID)
	if err := fd.SetDestinationDir(dir); err != nil {
		log.Warnf("failed to set default file drop destination: %v", err)
	}
}
