//go:build js || ios || android

package internal

import (
	log "github.com/sirupsen/logrus"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

type vncServer interface{}

func (e *Engine) updateVNC() error { return nil }

func (e *Engine) updateVNCServerAuth(auth *mgmProto.VNCAuth) {
	if auth == nil {
		return
	}
	log.Debugf("ignoring VNC auth push on platform without a VNC server: %d session pubkeys, %d authorized users",
		len(auth.GetSessionPubKeys()), len(auth.GetAuthorizedUsers()))
}

func (e *Engine) stopVNCServer() error { return nil }
