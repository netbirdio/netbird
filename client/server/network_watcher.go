package server

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/netevents/watcher"
	"github.com/netbirdio/netbird/client/proto"
)

func (s *Server) startNetworkWatcher() {
	ifaceName := ""
	if s.config != nil && s.config.WgIface != "" {
		ifaceName = s.config.WgIface
	}

	if ifaceName == "" {
		ifaceName = "wt0"
	}

	w := watcher.New(ifaceName)
	if w == nil {
		return
	}
	s.networkWatcher = w

	ctx := s.rootCtx
	log.Infof("starting network watcher for %s with root context", ifaceName)
	go func() {
		if err := w.Start(ctx, s); err != nil && !errors.Is(err, context.Canceled) {
			log.Warnf("network watcher stopped: %v", err)
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

		log.Infof("NetBird interface %s disconnected via network manager, taking connection down", ev.Name)
		go func() {
			if _, err := s.Down(s.rootCtx, &proto.DownRequest{}); err != nil {
				log.Debugf("failed to transition to Down on external disconnect: %v", err)
			}
		}()
	case watcher.EventUnderlyingVPNDisconnected:
		if s.netMgr != nil {
			s.netMgr.SetNetworkAvailable(false)
		}
		state := internal.CtxGetState(s.rootCtx)
		if state != nil {
			status, _ := state.Status()
			if status != internal.StatusConnected {
				log.Infof("ignoring disconnect event for %s because daemon status is %s (not Connected)", ev.Name, status)
				return
			}
		}

		log.Infof("underlying VPN %s disconnected via network manager, taking connection down", ev.Name)
		go func() {
			if _, err := s.Down(s.rootCtx, &proto.DownRequest{}); err != nil {
				log.Debugf("failed to transition to Down on external disconnect: %v", err)
			}
		}()
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
			state.Set(internal.StatusConnecting)
		}
	case watcher.EventNetworkConnected:
		log.Info("host network connected, resuming network availability")
		if s.netMgr != nil {
			s.netMgr.SetNetworkAvailable(true)
		}
	}
}
