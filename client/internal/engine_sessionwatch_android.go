//go:build android

package internal

import (
	"github.com/netbirdio/netbird/client/internal/auth/sessionwatch"
	"github.com/netbirdio/netbird/client/internal/peer"
)

func newSessionWatcher(recorder *peer.Status) sessionDeadlineWatcher {
	return sessionwatch.NewDeadlineOnly(recorder)
}
