package nat

import (
	"errors"
	"fmt"
	"github.com/pion/webrtc/v3"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee-signal/proto"
	"time"
)

// A set of tools to punch a UDP hole in NAT

// Uses WebRTC to probe the Network and gather connection Candidates.
// It is important to request this method with multiple STUN server URLs because NAT type can be detected out of the multiple Probes (candidates)
func PunchHole(stuns []string) ([]*proto.Candidate, error) {
	log.Debugf("starting to punch a NAT hole...")

	pConn, err := newPeerConnection(stuns)
	if err != nil {
		return nil, err
	}
	defer pConn.Close()

	var candidates []*proto.Candidate
	pConn.OnICEConnectionStateChange(func(connectionState webrtc.ICEConnectionState) {
		log.Debugf("ICE Connection State has changed: %s\n", connectionState.String())
	})
	pConn.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		log.Debugf("got new ICE candidate: %s", candidate)
		if candidate != nil {
			candidates = append(candidates, &proto.Candidate{
				//Address: fmt.Sprintf("%s:%d", candidate.Address, candidate.Port),
				Proto: candidate.Protocol.String(),
			})
		}
	})

	// Create an offer to send to the other process
	offer, err := pConn.CreateOffer(nil)
	if err != nil {
		return nil, err
	}
	// Sets the LocalDescription, and starts our UDP listeners
	// Note: this will start the gathering of ICE candidates
	if err = pConn.SetLocalDescription(offer); err != nil {
		panic(err)
	}

	gatherComplete := webrtc.GatheringCompletePromise(pConn)
	//wait for all the ICE candidates to be collected
	select {
	case <-gatherComplete:

		log.Debugf("collected %d candidates", len(candidates))

		return candidates, nil
	case <-time.After(time.Duration(10) * time.Second): //todo better timeout handling, or no timeout at all?
		return nil, errors.New(fmt.Sprintf("timeout of %v seconds reached while waiting for hole punching", 10))
	}
}

func newPeerConnection(stuns []string) (*webrtc.PeerConnection, error) {

	log.Debugf("creating new peer connection ...")
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: stuns,
			},
		},
	}
	settingEngine := webrtc.SettingEngine{}
	settingEngine.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeUDP4,
	})
	api := webrtc.NewAPI(
		webrtc.WithSettingEngine(settingEngine),
	)
	log.Debugf("created new peer connection")

	return api.NewPeerConnection(config)
}
