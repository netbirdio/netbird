package peer

import (
	"errors"
	"sync/atomic"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	signal "github.com/netbirdio/netbird/shared/signal/client"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

var (
	ErrPeerNotAvailable              = signal.ErrPeerNotAvailable
	ErrSignalNotSupportDeliveryCheck = errors.New("the signal client does not support SendWithDeliveryCheck")
)

type Signaler struct {
	signal       signal.Client
	wgPrivateKey wgtypes.Key

	deliveryCheckNotSupported atomic.Bool
}

func NewSignaler(signal signal.Client, wgPrivateKey wgtypes.Key) *Signaler {
	return &Signaler{
		signal:       signal,
		wgPrivateKey: wgPrivateKey,
	}
}

func (s *Signaler) SignalOffer(offer OfferAnswer, remoteKey string) error {
	return s.signalOfferAnswer(offer, remoteKey, sProto.Body_OFFER)
}

func (s *Signaler) SignalAnswer(offer OfferAnswer, remoteKey string) error {
	return s.signalOfferAnswer(offer, remoteKey, sProto.Body_ANSWER)
}

func (s *Signaler) SignalICECandidate(candidate ice.Candidate, remoteKey string) error {
	return s.signal.Send(&sProto.Message{
		Key:       s.wgPrivateKey.PublicKey().String(),
		RemoteKey: remoteKey,
		Body: &sProto.Body{
			Type:    sProto.Body_CANDIDATE,
			Payload: candidate.Marshal(),
		},
	})
}

func (s *Signaler) Ready() bool {
	return s.signal.Ready()
}

// SignalOfferAnswer signals either an offer or an answer to remote peer
func (s *Signaler) signalOfferAnswer(offerAnswer OfferAnswer, remoteKey string, bodyType sProto.Body_Type) error {
	sessionIDBytes, err := offerAnswer.SessionID.Bytes()
	if err != nil {
		log.Warnf("failed to get session ID bytes: %v", err)
	}
	msg, err := signal.MarshalCredential(
		s.wgPrivateKey,
		offerAnswer.WgListenPort,
		remoteKey,
		&signal.Credential{
			UFrag: offerAnswer.IceCredentials.UFrag,
			Pwd:   offerAnswer.IceCredentials.Pwd,
		},
		bodyType,
		offerAnswer.RosenpassPubKey,
		offerAnswer.RosenpassAddr,
		offerAnswer.RelaySrvAddress,
		sessionIDBytes)
	if err != nil {
		return err
	}

	if s.deliveryCheckNotSupported.Load() {
		return s.signal.Send(msg)
	}

	if err = s.signal.SendWithDeliveryCheck(msg); err != nil {
		switch {
		case errors.Is(err, signal.ErrPeerNotAvailable):
			return ErrPeerNotAvailable
		case errors.Is(err, signal.ErrUnimplementedMethod):
			s.deliveryCheckNotSupported.Store(true)
			return ErrSignalNotSupportDeliveryCheck
		default:
			return err
		}
	}
	return nil
}

func (s *Signaler) SignalIdle(remoteKey string) error {
	return s.signal.Send(&sProto.Message{
		Key:       s.wgPrivateKey.PublicKey().String(),
		RemoteKey: remoteKey,
		Body: &sProto.Body{
			Type: sProto.Body_GO_IDLE,
		},
	})
}
