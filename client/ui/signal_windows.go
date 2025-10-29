//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// setupSignalHandler sets up signal handling for Windows.
// Windows doesn't support SIGUSR1, so this is currently a no-op.
// Future enhancement: implement Windows-specific IPC (named events, named pipes, etc.)
func (s *serviceClient) setupSignalHandler(ctx context.Context) {
	// TODO: see how debug bundle is generated on signal in windows
	log.Debug("signal handler not yet implemented for Windows")
}

// openQuickActions opens the quick actions window by spawning a new process.
func (s *serviceClient) openQuickActions() {
	proc, err := os.Executable()
	if err != nil {
		log.Errorf("get executable path: %v", err)
		return
	}

	cmd := exec.CommandContext(s.ctx, proc,
		"--quick-actions=true",
		"--daemon-addr="+s.addr,
	)

	if out := s.attachOutput(cmd); out != nil {
		defer func() {
			if err := out.Close(); err != nil {
				log.Errorf("close log file %s: %v", s.logFile, err)
			}
		}()
	}

	log.Infof("running command: %s --quick-actions=true --daemon-addr=%s", proc, s.addr)

	if err := cmd.Start(); err != nil {
		log.Errorf("start quick actions window: %v", err)
		return
	}

	go func() {
		if err := cmd.Wait(); err != nil {
			log.Debugf("quick actions window exited: %v", err)
		}
	}()
}

func sendShowWindowSignal(pid int32) error {
	return fmt.Errorf("signal handler not yet implemented for Windows")
}
