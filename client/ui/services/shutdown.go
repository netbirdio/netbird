package services

import "sync/atomic"

var shuttingDown atomic.Bool

func BeginShutdown() {
	shuttingDown.Store(true)
}

func AbortShutdown() {
	shuttingDown.Store(false)
}

func ShuttingDown() bool {
	return shuttingDown.Load()
}
