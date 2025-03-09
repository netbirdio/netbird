package process

import (
	"os/user"

	"github.com/shirou/gopsutil/v3/process"
	log "github.com/sirupsen/logrus"
)

func isProcessOwnedByCurrentUser(p *process.Process) bool {
	processUsername, err := p.Username()
	if err != nil {
		log.Errorf("get process username error: %v", err)
		return false
	}

	currUser, err := user.Current()
	if err != nil {
		log.Errorf("get current user error: %v", err)
		return false
	}

	return processUsername == currUser.Username
}
