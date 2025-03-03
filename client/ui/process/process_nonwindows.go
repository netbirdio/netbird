//go:build !windows

package process

import (
	"os"

	"github.com/shirou/gopsutil/v3/process"
	log "github.com/sirupsen/logrus"
)

func isProcessOwnedByCurrentUser(p *process.Process) bool {
	currentUserID := os.Getuid()
	uids, err := p.Uids()
	if err != nil {
		log.Errorf("get process uids: %v", err)
		return false
	}
	for _, id := range uids {
		log.Debugf("checking process uid: %d", id)
		if int(id) == currentUserID {
			return true
		}
	}
	return false
}
