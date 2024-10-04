package peer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pion/ice/v3"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/stdnet"
)

const (
	signalerMonitorPeriod     = 5 * time.Second
	candidatesMonitorPeriod   = 5 * time.Minute
	candidateGatheringTimeout = 5 * time.Second
)

type ConnMonitor struct {
	signaler          *Signaler
	iFaceDiscover     stdnet.ExternalIFaceDiscover
	config            ConnConfig
	relayDisconnected chan bool
	iCEDisconnected   chan bool
	reconnectCh       chan struct{}
	currentCandidates []ice.Candidate
	candidatesMu      sync.Mutex
}

func NewConnMonitor(signaler *Signaler, iFaceDiscover stdnet.ExternalIFaceDiscover, config ConnConfig, relayDisconnected, iCEDisconnected chan bool) (*ConnMonitor, <-chan struct{}) {
	reconnectCh := make(chan struct{}, 1)
	cm := &ConnMonitor{
		signaler:          signaler,
		iFaceDiscover:     iFaceDiscover,
		config:            config,
		relayDisconnected: relayDisconnected,
		iCEDisconnected:   iCEDisconnected,
		reconnectCh:       reconnectCh,
	}
	return cm, reconnectCh
}

func (cm *ConnMonitor) Start(ctx context.Context) {
	signalerReady := make(chan struct{}, 1)
	go cm.monitorSignalerReady(ctx, signalerReady)

	localCandidatesChanged := make(chan struct{}, 1)
	go cm.monitorLocalCandidatesChanged(ctx, localCandidatesChanged)

	for {
		select {
		case changed := <-cm.relayDisconnected:
			if !changed {
				continue
			}
			log.Debugf("Relay state changed, triggering reconnect")
			cm.triggerReconnect()

		case changed := <-cm.iCEDisconnected:
			if !changed {
				continue
			}
			log.Debugf("ICE state changed, triggering reconnect")
			cm.triggerReconnect()

		case <-signalerReady:
			log.Debugf("Signaler became ready, triggering reconnect")
			cm.triggerReconnect()

		case <-localCandidatesChanged:
			log.Debugf("Local candidates changed, triggering reconnect")
			cm.triggerReconnect()

		case <-ctx.Done():
			return
		}
	}
}

func (cm *ConnMonitor) monitorSignalerReady(ctx context.Context, signalerReady chan<- struct{}) {
	if cm.signaler == nil {
		return
	}

	ticker := time.NewTicker(signalerMonitorPeriod)
	defer ticker.Stop()

	lastReady := true
	for {
		select {
		case <-ticker.C:
			currentReady := cm.signaler.Ready()
			if !lastReady && currentReady {
				select {
				case signalerReady <- struct{}{}:
				default:
				}
			}
			lastReady = currentReady
		case <-ctx.Done():
			return
		}
	}
}

func (cm *ConnMonitor) monitorLocalCandidatesChanged(ctx context.Context, localCandidatesChanged chan<- struct{}) {
	ufrag, pwd, err := generateICECredentials()
	if err != nil {
		log.Warnf("Failed to generate ICE credentials: %v", err)
		return
	}

	ticker := time.NewTicker(candidatesMonitorPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := cm.handleCandidateTick(ctx, localCandidatesChanged, ufrag, pwd); err != nil {
				log.Warnf("Failed to handle candidate tick: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (cm *ConnMonitor) handleCandidateTick(ctx context.Context, localCandidatesChanged chan<- struct{}, ufrag string, pwd string) error {
	log.Debugf("Gathering ICE candidates")

	transportNet, err := newStdNet(cm.iFaceDiscover, cm.config.ICEConfig.InterfaceBlackList)
	if err != nil {
		log.Errorf("failed to create pion's stdnet: %s", err)
	}

	agent, err := newAgent(cm.config, transportNet, candidateTypesP2P(), ufrag, pwd)
	if err != nil {
		return fmt.Errorf("create ICE agent: %w", err)
	}
	defer func() {
		if err := agent.Close(); err != nil {
			log.Warnf("Failed to close ICE agent: %v", err)
		}
	}()

	gatherDone := make(chan struct{})
	err = agent.OnCandidate(func(c ice.Candidate) {
		log.Tracef("Got candidate: %v", c)
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

	ctx, cancel := context.WithTimeout(ctx, candidateGatheringTimeout)
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

	if changed := cm.updateCandidates(candidates); changed {
		select {
		case localCandidatesChanged <- struct{}{}:
		default:
		}
	}

	return nil
}

func (cm *ConnMonitor) updateCandidates(newCandidates []ice.Candidate) bool {
	cm.candidatesMu.Lock()
	defer cm.candidatesMu.Unlock()

	if len(cm.currentCandidates) != len(newCandidates) {
		cm.currentCandidates = newCandidates
		return true
	}

	for i, candidate := range cm.currentCandidates {
		if candidate.Address() != newCandidates[i].Address() {
			cm.currentCandidates = newCandidates
			return true
		}
	}

	return false
}

func (cm *ConnMonitor) triggerReconnect() {
	select {
	case cm.reconnectCh <- struct{}{}:
	default:
	}
}
