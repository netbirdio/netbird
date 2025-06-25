package ice

import (
	"time"

	"github.com/pion/ice/v3"
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
	// iceRelayAcceptanceMinWaitDefault is the same as in the Pion ICE package
	iceRelayAcceptanceMinWaitDefault = 2 * time.Second
)

var (
	failedTimeout = 6 * time.Second
)

func NewAgent(iFaceDiscover stdnet.ExternalIFaceDiscover, config Config, candidateTypes []ice.CandidateType, ufrag string, pwd string) (*ice.Agent, error) {
	iceKeepAlive := iceKeepAlive()
	iceDisconnectedTimeout := iceDisconnectedTimeout()
	iceRelayAcceptanceMinWait := iceRelayAcceptanceMinWait()

	transportNet, err := newStdNet(iFaceDiscover, config.InterfaceBlackList)
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
		FailedTimeout:          &failedTimeout,
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

	return ice.NewAgent(agentConfig)
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
