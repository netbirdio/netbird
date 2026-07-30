package services

import "sync/atomic"

var (
	sessionEnding atomic.Bool
	quitting      atomic.Bool
)

func BeginSessionEnd() {
	sessionEnding.Store(true)
}

func AbortSessionEnd() {
	sessionEnding.Store(false)
}

func BeginShutdown() {
	quitting.Store(true)
}

func ShuttingDown() bool {
	return sessionEnding.Load() || quitting.Load()
}
