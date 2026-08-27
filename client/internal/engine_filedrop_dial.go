//go:build !ios

package internal

import (
	"net"

	"github.com/netbirdio/netbird/client/internal/filedrop"
)

func fileDropOSDial(WGIface) filedrop.DialFunc {
	dialer := &net.Dialer{}
	return dialer.DialContext
}

func fileDropListenControl(WGIface) filedrop.ListenControl {
	return nil
}
