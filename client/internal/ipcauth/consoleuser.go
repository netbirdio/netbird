package ipcauth

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

// logConsolePanic keeps the notice to once per process.
var logConsolePanic sync.Once

// IsConsoleUser reports whether a caller is sitting at one of this machine's
// consoles right now.
//
// It is false on a headless machine, which has no seat to sit at, on a
// platform that exposes no console-user lookup at all, and whenever the lookup
// fails. Callers must read that as "cannot confirm" rather than as proof of
// absence. It gates handing out ownership, so a lookup that cannot answer
// withholds a claim, and never grants one.
func IsConsoleUser(id Identity) bool {
	if !id.Known() {
		return false
	}

	return guardConsoleLookup(id, isConsoleUser)
}

// consoleLookup is a variable so a test can decide whether a caller is at the
// console without the machine running it having a seat of its own.
var consoleLookup = IsConsoleUser

// guardConsoleLookup runs a platform lookup and turns a panic out of it into
// "cannot confirm".
func guardConsoleLookup(id Identity, lookup func(Identity) bool) (atConsole bool) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		atConsole = false
		logConsolePanic.Do(func() {
			log.Errorf("console user lookup panicked, no caller will be treated as being at the console: %v", r)
		})
	}()

	return lookup(id)
}
