package guard

import (
	"os"
	"strconv"
	"time"
)

const (
	envICEMonitorPeriod = "NB_ICE_MONITOR_PERIOD"
)

func GetICEMonitorPeriod() time.Duration {
	if envVal := os.Getenv(envICEMonitorPeriod); envVal != "" {
		if seconds, err := strconv.Atoi(envVal); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return defaultCandidatesMonitorPeriod
}
