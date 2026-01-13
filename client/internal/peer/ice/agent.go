package ice

import (
	"context"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/randutil"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/stdnet"
)

const (
	lenUFrag   = 16
	lenPwd     = 32
	runesAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	iceKeepAliveDefault           = 4 * time.Second
	iceDisconnectedTimeoutDefault = 6 * time.Second
	iceFailedTimeoutDefault       = 6 * time.Second
	// iceRelayAcceptanceMinWaitDefault is the same as in the Pion ICE package
	iceRelayAcceptanceMinWaitDefault = 2 * time.Second
	// iceAgentCloseTimeout is the maximum time to wait for ICE agent close to complete
	iceAgentCloseTimeout = 3 * time.Second
)

type ThreadSafeAgent struct {
	*ice.Agent
	once sync.Once
}

func (a *ThreadSafeAgent) Close() error {
	var err error
	a.once.Do(func() {
		done := make(chan error, 1)
		go func() {
			done <- a.Agent.Close()
		}()

		select {
		case err = <-done:
		case <-time.After(iceAgentCloseTimeout):
			log.Warnf("ICE agent close timed out after %v, proceeding with cleanup", iceAgentCloseTimeout)
			err = nil
		}
	})
	return err
}

func NewAgent(ctx context.Context, iFaceDiscover stdnet.ExternalIFaceDiscover, config Config, candidateTypes []ice.CandidateType, ufrag string, pwd string) (*ThreadSafeAgent, error) {
	iceKeepAlive := iceKeepAlive()
	iceDisconnectedTimeout := iceDisconnectedTimeout()
	iceFailedTimeout := iceFailedTimeout()
	iceRelayAcceptanceMinWait := iceRelayAcceptanceMinWait()

	transportNet, err := newStdNet(ctx, iFaceDiscover, config.InterfaceBlackList)
	if err != nil {
		log.Errorf("failed to create pion's stdnet: %s", err)
	}

	fac := logging.NewDefaultLoggerFactory()

	//fac.Writer = log.StandardLogger().Writer()

	agentConfig := &ice.AgentConfig{
		MulticastDNSMode:       ice.MulticastDNSModeDisabled,
		NetworkTypes:           []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		Urls:                   config.StunTurn.Load(),
		CandidateTypes:         candidateTypes,
		InterfaceFilter:        stdnet.InterfaceFilter(config.InterfaceBlackList),
		UDPMux:                 config.UDPMux,
		UDPMuxSrflx:            config.UDPMuxSrflx,
		NAT1To1IPs:             config.NATExternalIPs,
		Net:                    transportNet,
		FailedTimeout:          &iceFailedTimeout,
		DisconnectedTimeout:    &iceDisconnectedTimeout,
		KeepaliveInterval:      &iceKeepAlive,
		RelayAcceptanceMinWait: &iceRelayAcceptanceMinWait,
		LocalUfrag:             ufrag,
		LocalPwd:               pwd,
		LoggerFactory:          fac,
	}

	if config.DisableIPv6Discovery {
		agentConfig.NetworkTypes = []ice.NetworkType{ice.NetworkTypeUDP4}
	}

	agent, err := ice.NewAgent(agentConfig)
	if err != nil {
		return nil, err
	}

	return &ThreadSafeAgent{Agent: agent}, nil
}

func GenerateICECredentials() (string, string, error) {
	ufrag, err := randutil.GenerateCryptoRandomString(lenUFrag, runesAlpha)
	if err != nil {
		return "", "", err
	}

	pwd, err := randutil.GenerateCryptoRandomString(lenPwd, runesAlpha)
	if err != nil {
		return "", "", err
	}
	return ufrag, pwd, nil
}

func CandidateTypes() []ice.CandidateType {
	if hasICEForceRelayConn() {
		return []ice.CandidateType{ice.CandidateTypeRelay}
	}

	return []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay}
}

func CandidateTypesP2P() []ice.CandidateType {
	return []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}
}
