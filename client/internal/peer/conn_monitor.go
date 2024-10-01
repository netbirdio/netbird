package peer

import (
	"context"
	"fmt"
	"time"

	"github.com/pion/ice/v3"
	log "github.com/sirupsen/logrus"
)

func (conn *Conn) monitorReconnectEvents() {
	signalerReady := make(chan struct{}, 1)
	go conn.monitorSignalerReady(signalerReady)

	localCandidatesChanged := make(chan struct{}, 1)
	go conn.monitorLocalCandidatesChanged(localCandidatesChanged)

	for {
		select {
		case changed := <-conn.relayDisconnected:
			if !changed {
				continue
			}

			conn.log.Debugf("Relay state changed, triggering reconnect")
			conn.triggerReconnect()

		case changed := <-conn.iCEDisconnected:
			if !changed {
				continue
			}

			conn.log.Debugf("ICE state changed, triggering reconnect")
			conn.triggerReconnect()

		case <-signalerReady:
			conn.log.Debugf("Signaler became ready, triggering reconnect")
			conn.triggerReconnect()

		case <-localCandidatesChanged:
			conn.log.Debugf("Local candidates changed, triggering reconnect")
			conn.triggerReconnect()

		case <-conn.ctx.Done():
			return
		}
	}
}

// monitorSignalerReady monitors the signaler ready state and triggers reconnect when it transitions from not ready to ready
func (conn *Conn) monitorSignalerReady(signalerReady chan<- struct{}) {
	ticker := time.NewTicker(signalerMonitorPeriod)
	defer ticker.Stop()

	lastReady := true
	for {
		select {
		case <-ticker.C:
			currentReady := conn.signaler.Ready()
			if !lastReady && currentReady {
				select {
				case signalerReady <- struct{}{}:
				default:
				}
			}
			lastReady = currentReady
		case <-conn.ctx.Done():
			return
		}
	}
}

// monitorLocalCandidatesChanged monitors the local candidates and triggers reconnect when they change
func (conn *Conn) monitorLocalCandidatesChanged(localCandidatesChanged chan<- struct{}) {
	// TODO: make this global and not per-conn

	ufrag, pwd, err := generateICECredentials()
	if err != nil {
		conn.log.Warnf("Failed to generate ICE credentials: %v", err)
		return
	}

	ticker := time.NewTicker(candidatesMonitorPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := conn.handleCandidateTick(localCandidatesChanged, ufrag, pwd); err != nil {
				conn.log.Warnf("Failed to handle candidate tick: %v", err)
			}
		case <-conn.ctx.Done():
			return
		}
	}
}

func (conn *Conn) handleCandidateTick(localCandidatesChanged chan<- struct{}, ufrag string, pwd string) error {
	conn.log.Debugf("Gathering ICE candidates")

	transportNet, err := newStdNet(conn.iFaceDiscover, conn.config.ICEConfig.InterfaceBlackList)
	if err != nil {
		conn.log.Errorf("failed to create pion's stdnet: %s", err)
	}

	agent, err := newAgent(conn.config, transportNet, candidateTypesP2P(), ufrag, pwd)
	if err != nil {
		return fmt.Errorf("create ICE agent: %w", err)
	}
	defer func() {
		if err := agent.Close(); err != nil {
			conn.log.Warnf("Failed to close ICE agent: %v", err)
		}
	}()

	gatherDone := make(chan struct{})
	err = agent.OnCandidate(func(c ice.Candidate) {
		log.Debugf("Got candidate: %v", c)
		if c == nil {
			close(gatherDone)
		}
	})
	if err != nil {
		return fmt.Errorf("set ICE candidate handler: %w", err)
	}

	if err := agent.GatherCandidates(); err != nil {
		return fmt.Errorf("gather ICE candidates: %w", err)
	}

	ctx, cancel := context.WithTimeout(conn.ctx, candidatedGatheringTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return fmt.Errorf("wait for gathering: %w", ctx.Err())
	case <-gatherDone:
	}

	candidates, err := agent.GetLocalCandidates()
	if err != nil {
		return fmt.Errorf("get local candidates: %w", err)
	}
	log.Tracef("Got candidates: %v", candidates)

	if changed := conn.updateCandidates(candidates); changed {
		select {
		case localCandidatesChanged <- struct{}{}:
		default:
		}
	}

	return nil
}

func (conn *Conn) updateCandidates(newCandidates []ice.Candidate) bool {
	conn.candidatesMu.Lock()
	defer conn.candidatesMu.Unlock()

	if len(conn.currentCandidates) != len(newCandidates) {
		conn.currentCandidates = newCandidates
		return true
	}

	for i, candidate := range conn.currentCandidates {
		if candidate.String() != newCandidates[i].String() {
			conn.currentCandidates = newCandidates
			return true
		}
	}

	return false
}

func (conn *Conn) triggerReconnect() {
	select {
	case conn.reconnectCh <- struct{}{}:
	default:
	}
}
