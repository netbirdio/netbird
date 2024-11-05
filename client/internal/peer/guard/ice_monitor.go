package guard

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pion/ice/v3"
	log "github.com/sirupsen/logrus"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

const (
	candidatesMonitorPeriod   = 5 * time.Minute
	candidateGatheringTimeout = 5 * time.Second
)

type ICEMonitor struct {
	ReconnectCh chan struct{}

	iFaceDiscover stdnet.ExternalIFaceDiscover
	iceConfig     icemaker.Config

	currentCandidates []ice.Candidate
	candidatesMu      sync.Mutex
}

func NewICEMonitor(iFaceDiscover stdnet.ExternalIFaceDiscover, config icemaker.Config) *ICEMonitor {
	cm := &ICEMonitor{
		ReconnectCh:   make(chan struct{}, 1),
		iFaceDiscover: iFaceDiscover,
		iceConfig:     config,
	}
	return cm
}

func (cm *ICEMonitor) Start(ctx context.Context, onChanged func()) {
	ufrag, pwd, err := icemaker.GenerateICECredentials()
	if err != nil {
		log.Warnf("Failed to generate ICE credentials: %v", err)
		return
	}

	ticker := time.NewTicker(candidatesMonitorPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			changed, err := cm.handleCandidateTick(ctx, ufrag, pwd)
			if err != nil {
				log.Warnf("Failed to check ICE changes: %v", err)
				continue
			}

			if changed {
				onChanged()
			}
		case <-ctx.Done():
			return
		}
	}
}

func (cm *ICEMonitor) handleCandidateTick(ctx context.Context, ufrag string, pwd string) (bool, error) {
	log.Debugf("Gathering ICE candidates")

	agent, err := icemaker.NewAgent(cm.iFaceDiscover, cm.iceConfig, candidateTypesP2P(), ufrag, pwd)
	if err != nil {
		return false, fmt.Errorf("create ICE agent: %w", err)
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
		return false, fmt.Errorf("set ICE candidate handler: %w", err)
	}

	if err := agent.GatherCandidates(); err != nil {
		return false, fmt.Errorf("gather ICE candidates: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, candidateGatheringTimeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return false, fmt.Errorf("wait for gathering timed out")
	case <-gatherDone:
	}

	candidates, err := agent.GetLocalCandidates()
	if err != nil {
		return false, fmt.Errorf("get local candidates: %w", err)
	}
	log.Tracef("Got candidates: %v", candidates)

	return cm.updateCandidates(candidates), nil
}

func (cm *ICEMonitor) updateCandidates(newCandidates []ice.Candidate) bool {
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

func candidateTypesP2P() []ice.CandidateType {
	return []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}
}
