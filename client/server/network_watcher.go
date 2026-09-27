package server

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/netevents/watcher"
	"github.com/netbirdio/netbird/client/proto"
)

func (s *Server) ensureNetworkWatcher(ifaceName string) {
	if ifaceName == "" {
		ifaceName = "wt0"
	}

	s.mutex.Lock()
	if s.networkWatcher != nil && s.networkWatcherIface == ifaceName {
		s.mutex.Unlock()
		return
	}
	oldWatcher := s.networkWatcher
	w := watcher.New(ifaceName)
	if w == nil {
		s.mutex.Unlock()
		return
	}
	s.networkWatcher = w
	s.networkWatcherIface = ifaceName
	s.mutex.Unlock()

	if oldWatcher != nil {
		_ = oldWatcher.Stop()
	}

	ctx := s.rootCtx
	log.Infof("starting network watcher for %s with root context", ifaceName)
	go func() {
		if err := w.Start(ctx, s); err != nil && !errors.Is(err, context.Canceled) {
			log.Warnf("network watcher stopped: %v", err)
			s.mutex.Lock()
			if s.networkWatcher == w {
				s.networkWatcher = nil
				s.networkWatcherIface = ""
			}
			s.mutex.Unlock()
		} else {
			log.Infof("network watcher exited cleanly: %v", err)
		}
	}()
}

// OnNetworkEvent handles events forwarded from the OS network watcher.
func (s *Server) OnNetworkEvent(ev watcher.Event) {
	log.Infof("network event received: kind=%s, name=%s, reason=%s, userInitiated=%t",
		ev.Kind, ev.Name, ev.Reason, ev.UserInitiated)

	switch ev.Kind {
	case watcher.EventNetBirdInterfaceDisconnected:
		state := internal.CtxGetState(s.rootCtx)
		if state != nil {
			status, _ := state.Status()
			if status != internal.StatusConnected {
				log.Infof("ignoring disconnect event for %s because daemon status is %s (not Connected)", ev.Name, status)
				return
			}
		}

		s.mutex.Lock()
		running := s.clientRunning
		s.mutex.Unlock()
		if !running {
			log.Infof("ignoring disconnect event for %s because daemon is not running", ev.Name)
			return
		}

		log.Infof("NetBird interface %s disconnected via network manager, taking connection down", ev.Name)
		go func() {
			if s.downFn != nil {
				_, _ = s.downFn(s.rootCtx, &proto.DownRequest{})
				return
			}
			if _, err := s.Down(s.rootCtx, &proto.DownRequest{}); err != nil {
				log.Debugf("failed to transition to Down on external disconnect: %v", err)
			}
		}()
	case watcher.EventUnderlyingVPNDisconnected:
		log.Infof("underlying VPN %s disconnected, marking network unavailable", ev.Name)
		if s.netMgr != nil {
			s.netMgr.SetNetworkAvailable(false)
		}
	case watcher.EventUnderlyingVPNConnected:
		log.Infof("underlying VPN %s connected, resuming network availability", ev.Name)
		if s.netMgr != nil {
			s.netMgr.SetNetworkAvailable(true)
		}
	case watcher.EventNetworkDisconnected:
		log.Info("host network disconnected, marking network unavailable")
		if s.netMgr != nil {
			s.netMgr.SetNetworkAvailable(false)
		}
		if state := internal.CtxGetState(s.rootCtx); state != nil {
			if status, _ := state.Status(); status == internal.StatusConnected {
				state.Set(internal.StatusConnecting)
			}
		}
	case watcher.EventNetworkConnected:
		log.Info("host network connected, resuming network availability")
		if s.netMgr != nil {
			s.netMgr.SetNetworkAvailable(true)
		}
	}
}
