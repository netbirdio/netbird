package guard

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

const (
	defaultCandidatesMonitorPeriod = 5 * time.Minute
	candidateGatheringTimeout      = 5 * time.Second
)

type ICEMonitor struct {
	ReconnectCh chan struct{}

	iFaceDiscover stdnet.ExternalIFaceDiscover
	iceConfig     icemaker.Config
	tickerPeriod  time.Duration

	currentCandidatesAddress []string
	candidatesMu             sync.Mutex
}

func NewICEMonitor(iFaceDiscover stdnet.ExternalIFaceDiscover, config icemaker.Config, period time.Duration) *ICEMonitor {
	log.Debugf("prepare ICE monitor with period: %s", period)
	cm := &ICEMonitor{
		ReconnectCh:   make(chan struct{}, 1),
		iFaceDiscover: iFaceDiscover,
		iceConfig:     config,
		tickerPeriod:  period,
	}
	return cm
}

func (cm *ICEMonitor) Start(ctx context.Context, onChanged func()) {
	ufrag, pwd, err := icemaker.GenerateICECredentials()
	if err != nil {
		log.Warnf("Failed to generate ICE credentials: %v", err)
		return
	}

	// Initial check to populate the candidates for later comparison
	if _, err := cm.handleCandidateTick(ctx, ufrag, pwd); err != nil {
		log.Warnf("Failed to check initial ICE candidates: %v", err)
	}

	ticker := time.NewTicker(cm.tickerPeriod)
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

	agent, err := icemaker.NewAgent(ctx, cm.iFaceDiscover, cm.iceConfig, candidateTypesP2P(), ufrag, pwd)
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

	newAddresses := make([]string, len(newCandidates))
	for i, c := range newCandidates {
		newAddresses[i] = c.Address()
	}
	sort.Strings(newAddresses)

	if len(cm.currentCandidatesAddress) != len(newAddresses) {
		cm.currentCandidatesAddress = newAddresses
		return true
	}

	// Compare elements
	if !slices.Equal(cm.currentCandidatesAddress, newAddresses) {
		cm.currentCandidatesAddress = newAddresses
		return true
	}

	return false
}

func candidateTypesP2P() []ice.CandidateType {
	return []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}
}
