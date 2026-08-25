//go:build android

package android

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
)

// SetFileDropSink installs the platform sink incoming payloads are staged
// through. It takes effect on the next handle the client opens, so the platform
// sets it before asking for one.
func (c *Client) SetFileDropSink(sink FileDropSink) {
	c.fileDropMu.Lock()
	defer c.fileDropMu.Unlock()
	c.fileDropSink = sink
}

// FileDrop returns the handle of the active profile, creating it on first use.
// The UI calls this to list transfers and change settings while disconnected.
func (c *Client) FileDrop(configDir string) (*FileDrop, error) {
	profile, err := NewProfileManager(configDir).GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}
	return c.fileDropFor(configDir, profile.ID)
}

// fileDropFor returns the handle of one profile, replacing the cached one when
// the profile changed. The listener is carried over so a profile switch does not
// silence the UI.
func (c *Client) fileDropFor(configDir, profileID string) (*FileDrop, error) {
	c.fileDropMu.Lock()

	if c.fileDrop != nil && c.fileDrop.ProfileID() == profileID {
		fd := c.fileDrop
		c.fileDropMu.Unlock()
		return fd, nil
	}

	fd, err := NewFileDrop(configDir, profileID, c.fileDropSink)
	if err != nil {
		c.fileDropMu.Unlock()
		return nil, err
	}
	ensureFileDropDestination(fd)

	old := c.fileDrop
	if old != nil {
		fd.SetListener(old.Listener())
	}
	c.fileDrop = fd
	c.fileDropMu.Unlock()

	// Closing waits out the in-flight uploads of the profile being left, which is
	// far too long to hold the lock every caller of this goes through.
	if old != nil {
		if err := old.Close(); err != nil {
			log.Warnf("failed to close previous file drop manager: %v", err)
		}
	}

	return fd, nil
}

// attachFileDrop hands the connect client the file drop manager of the profile
// the engine is starting for. The profile is derived from the config path rather
// than read from the active profile state, so a switch racing the startup cannot
// pair one profile's engine with another's transfers. A failure is not fatal:
// the tunnel is worth more than the feature, so the engine runs on without it.
func (c *Client) attachFileDrop(cc *internal.ConnectClient, cfgFile string) {
	configDir, profileID, err := profileLocationFor(cfgFile)
	if err != nil {
		log.Warnf("file drop is unavailable: %v", err)
		return
	}

	fd, err := c.fileDropFor(configDir, profileID)
	if err != nil {
		log.Warnf("file drop is unavailable: %v", err)
		return
	}
	cc.SetFileDropManager(fd.manager)
}
