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

	if s.networkWatcher != nil && s.networkWatcherIface == ifaceName {
		return
	}
	oldWatcher := s.networkWatcher
	s.hostNetworkOffline = false
	if s.offlineVPNs != nil {
		clear(s.offlineVPNs)
	}
	w := watcher.New(ifaceName)
	if w == nil {
		s.networkWatcher = nil
		s.networkWatcherIface = ""
		s.publishAggregateNetworkAvailabilityLocked()
		return
	}
	s.networkWatcher = w
	s.networkWatcherIface = ifaceName
	s.publishAggregateNetworkAvailabilityLocked()

	if oldWatcher != nil {
		go func(ow watcher.Watcher) {
			_ = ow.Stop()
		}(oldWatcher)
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
				s.hostNetworkOffline = false
				if s.offlineVPNs != nil {
					clear(s.offlineVPNs)
				}
				s.publishAggregateNetworkAvailabilityLocked()
			}
			s.mutex.Unlock()
		} else {
			log.Infof("network watcher exited cleanly: %v", err)
		}
	}()
}

func (s *Server) setNetworkOffline(offline bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.hostNetworkOffline = offline
	s.publishAggregateNetworkAvailabilityLocked()
}

func (s *Server) setVPNOffline(name string, offline bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.offlineVPNs == nil {
		s.offlineVPNs = make(map[string]struct{})
	}
	if offline {
		if name != "" {
			s.offlineVPNs[name] = struct{}{}
		} else {
			s.offlineVPNs["default"] = struct{}{}
		}
	} else {
		if name != "" {
			delete(s.offlineVPNs, name)
		} else {
			clear(s.offlineVPNs)
		}
	}
	s.publishAggregateNetworkAvailabilityLocked()
}

func (s *Server) publishAggregateNetworkAvailabilityLocked() {
	available := !s.hostNetworkOffline && len(s.offlineVPNs) == 0
	if s.netMgr != nil {
		s.netMgr.SetNetworkAvailable(available)
	}
}

// OnNetworkEvent handles events forwarded from the OS network watcher.
func (s *Server) OnNetworkEvent(ev watcher.Event) {
	log.Infof("network event received: kind=%s, name=%s, reason=%s, userInitiated=%t",
		ev.Kind, ev.Name, ev.Reason, ev.UserInitiated)

	switch ev.Kind {
	case watcher.EventNetBirdInterfaceDisconnected:
		s.handleInterfaceDisconnected(ev)

	case watcher.EventUnderlyingVPNDisconnected:
		log.Infof("underlying VPN %s disconnected, marking network unavailable", ev.Name)
		s.setVPNOffline(ev.Name, true)

	case watcher.EventUnderlyingVPNConnected:
		log.Infof("underlying VPN %s connected, evaluating network availability", ev.Name)
		s.setVPNOffline(ev.Name, false)

	case watcher.EventNetworkDisconnected:
		log.Info("host network disconnected, marking network unavailable")
		s.setNetworkOffline(true)
		state := internal.CtxGetState(s.rootCtx)
		if status, _ := state.Status(); status == internal.StatusConnected {
			state.Set(internal.StatusConnecting)
		}

	case watcher.EventNetworkConnected:
		log.Info("host network connected, evaluating network availability")
		s.setNetworkOffline(false)
	}
}

func (s *Server) handleInterfaceDisconnected(ev watcher.Event) {
	state := internal.CtxGetState(s.rootCtx)
	if status, _ := state.Status(); status != internal.StatusConnected {
		log.Infof("ignoring disconnect event for %s because daemon status is %s (not Connected)", ev.Name, status)
		return
	}

	s.mutex.Lock()
	currentIface := s.networkWatcherIface
	running := s.clientRunning
	s.mutex.Unlock()

	if currentIface == "" || ev.Name == "" || ev.Name != currentIface {
		log.Infof("ignoring disconnect event for %s because current watcher interface is %s", ev.Name, currentIface)
		return
	}

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
}
