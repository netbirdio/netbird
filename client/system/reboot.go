package system

import (
	"time"

	"github.com/shirou/gopsutil/host"
	log "github.com/sirupsen/logrus"
)

func lastReboot() string {
	info, err := host.Info()
	if err != nil {
		log.Errorf("failed to get boot time: %s", err)
		return ""
	}
	return time.Unix(int64(info.BootTime), 0).String()
}
