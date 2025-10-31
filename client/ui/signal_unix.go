//go:build !windows && !(linux && 386)

package main

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// setupSignalHandler sets up a signal handler to listen for SIGUSR1.
// When received, it opens the quick actions window.
func (s *serviceClient) setupSignalHandler(ctx context.Context) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGUSR1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigChan:
				log.Info("received SIGUSR1 signal, opening quick actions window")
				s.openQuickActions()
			}
		}
	}()
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

// sendShowWindowSignal sends SIGUSR1 to the specified PID.
func sendShowWindowSignal(pid int32) error {
	process, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}
	return process.Signal(syscall.SIGUSR1)
}
