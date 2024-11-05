//go:build android || (ios && !darwin)

package iface

import "errors"

func (w *WGIface) Destroy() error {
	return errors.New("not supported on mobile")
}
