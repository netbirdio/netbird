package internal

import (
	"errors"
)

// SetLazyConnEnabled applies a local lazy connection override to the running
// engine. It pins the setting like an env/CLI flag, so a later management sync
// cannot override it. syncMsgMux guards ConnMgr, which is not thread-safe.
func (e *Engine) SetLazyConnEnabled(enabled bool) error {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	if e.connMgr == nil {
		return errors.New("connection manager is not initialised")
	}

	return e.connMgr.SetLocalLazyConn(e.ctx, enabled)
}
