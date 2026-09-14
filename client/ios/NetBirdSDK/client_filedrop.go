//go:build ios

package NetBirdSDK

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/mobile"
)

// FileDropHandle returns the file drop handle of the client's profile, creating it on first use.
func (c *Client) FileDropHandle() (*FileDrop, error) {
	configDir, profileID, err := mobile.ProfileLocationFor(c.cfgFile)
	if err != nil {
		return nil, err
	}
	return c.fileDropFor(configDir, profileID)
}

func (c *Client) fileDropFor(configDir, profileID string) (*FileDrop, error) {
	c.fileDropMu.Lock()

	if c.fileDrop != nil && c.fileDrop.ProfileID() == profileID {
		fd := c.fileDrop
		c.fileDropMu.Unlock()
		return fd, nil
	}

	fd, err := NewFileDrop(configDir, profileID)
	if err != nil {
		c.fileDropMu.Unlock()
		return nil, err
	}

	old := c.fileDrop
	if old != nil {
		fd.SetListener(old.Listener())
	}
	c.fileDrop = fd
	c.fileDropMu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			log.Warnf("failed to close previous file drop manager: %v", err)
		}
	}

	return fd, nil
}

func (c *Client) attachFileDrop(cc *internal.ConnectClient, cfgFile string) {
	configDir, profileID, err := mobile.ProfileLocationFor(cfgFile)
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
