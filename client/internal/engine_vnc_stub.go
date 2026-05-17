//go:build js || ios || android

package internal

import (
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

type vncServer interface{}

func (e *Engine) updateVNC(_ *mgmProto.SSHConfig) error { return nil }

func (e *Engine) updateVNCServerAuth(_ *mgmProto.VNCAuth) {}

func (e *Engine) stopVNCServer() error { return nil }
