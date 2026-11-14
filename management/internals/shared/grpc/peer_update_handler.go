package grpc

import (
	"context"
	"time"

	pb "github.com/golang/protobuf/proto" //nolint
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func PeerUpdateHandlerFactory(
	peerKey wgtypes.Key,
	updates chan *network_map.UpdateMessage,
	secretsManager SecretsManager,
	challenger *certposture.Challenger,
	onChallengeStamped func(),
	srv proto.ManagementService_SyncServer,
	cleanupfunc func()) *PeerUpdateHandler {
	return &PeerUpdateHandler{
		peerKey:            peerKey,
		updates:            updates,
		secretsManager:     secretsManager,
		challenger:         challenger,
		onChallengeStamped: onChallengeStamped,
		srv:                srv,
		encrypter:          &streamEncrypter{},
		debouncer:          NewUpdateDebouncer(1000 * time.Millisecond),
		cleanupFunc:        cleanupfunc,
	}
}

// PeerUpdateHandler sends updates to the connected peer until the updates channel is closed.
// It implements a backpressure mechanism that sends the first update immediately,
// then debounces subsequent rapid updates, ensuring only the latest update is sent
// after a quiet period.
type PeerUpdateHandler struct {
	peerKey        wgtypes.Key
	updates        chan *network_map.UpdateMessage
	appMetrics     telemetry.AppMetrics
	secretsManager SecretsManager
	challenger     *certposture.Challenger
	// onChallengeStamped registers the account for renewal. Every push reaches this
	// path, including the ones a REST update on another instance broadcasts, which is
	// what lets an instance pick up an account whose peers never reconnect.
	onChallengeStamped func()
	srv                syncSender
	encrypter          encryption.Encrypter
	// srvKey is the server key srvPubKey was derived from. The public key is
	// derived once per stream (and again only if the server key changes)
	// instead of on every send. Only HandleUpdates touches these fields.
	srvKey      wgtypes.Key
	srvPubKey   string
	debouncer   Debouncer
	cleanupFunc func()
	// aligned is the aligned heartbeat confirmed on this stream, nil when off.
	// Only HandleUpdates touches it once it runs.
	aligned *alignedHeartbeat
	// signer signs the phase of the new day, nil when phases are not re-signed.
	signer *phasesig.Signer
	// newTicker starts the heartbeat tick, alignedhb.Ticker when nil. Tests set
	// it to drive the tick by hand.
	newTicker func(ctx context.Context, period, phase time.Duration, now func() time.Time) <-chan time.Time
}

// streamEncrypter encrypts the messages of one stream. It derives the box
// shared key once per server key with box.Precompute (through
// encryption.SharedKeyCache) and seals with box.SealAfterPrecomputation,
// instead of deriving it on every message. Every message still gets its own
// random nonce, and the wire format is unchanged, so the stock client
// decrypt path (box.Open) reads it as before. A new server key derives a
// new shared key. Only the stream's send loop calls it.
type streamEncrypter struct {
	cache *encryption.SharedKeyCache
	key   wgtypes.Key
}

func (pu *PeerUpdateHandler) WithMetrics(appMetrics telemetry.AppMetrics) *PeerUpdateHandler {
	pu.appMetrics = appMetrics
	return pu
}

// WithAlignedHeartbeat turns on the aligned heartbeat confirmed on this stream.
// signer re-signs the phase when the day changes. A nil aligned leaves the
// stream stock.
func (pu *PeerUpdateHandler) WithAlignedHeartbeat(aligned *alignedHeartbeat, signer *phasesig.Signer) *PeerUpdateHandler {
	pu.aligned = aligned
	pu.signer = signer
	return pu
}

// heartbeatTick returns the aligned heartbeat tick and its stop func. The tick
// is nil (never fires) on a stock stream.
func (pu *PeerUpdateHandler) heartbeatTick(ctx context.Context) (<-chan time.Time, context.CancelFunc) {
	if pu.aligned == nil {
		return nil, func() {}
	}
	sched := pu.aligned.answer
	log.WithContext(ctx).Debugf("aligned heartbeat on for peer %s, period %s, phase %d ms",
		pu.peerKey.String(), sched.Period, sched.Phase.Milliseconds())
	tickCtx, cancel := context.WithCancel(ctx)
	newTicker := pu.newTicker
	if newTicker == nil {
		newTicker = alignedhb.Ticker
	}
	return newTicker(tickCtx, sched.Period, sched.Phase, time.Now), cancel
}

// nextHeartbeat returns the heartbeat for this tick. The first tick after the
// day change signs the phase of the new day, sends it with the heartbeat and
// reports moved, so the caller moves the tick to it.
func (pu *PeerUpdateHandler) nextHeartbeat(ctx context.Context, now time.Time) (update *network_map.UpdateMessage, moved bool) {
	next := pu.aligned.resign(pu.signer, pu.peerKey, now)
	if next == nil {
		return heartbeatUpdate(nil), false
	}
	log.WithContext(ctx).Debugf("aligned heartbeat for peer %s moves to phase %d ms of day %d",
		pu.peerKey.String(), next.answer.Phase.Milliseconds(), next.signed.Day)
	pu.aligned = next
	return heartbeatUpdate(next.config()), true
}

//go:generate go tool mockgen -source=./peer_update_handler.go -destination=./sync_sender_mock.go -package=grpc
type syncSender interface {
	Send(*proto.EncryptedMessage) error
	Context() context.Context
}

func (pu *PeerUpdateHandler) HandleUpdates(ctx context.Context) error {
	log.WithContext(ctx).Tracef("starting to handle updates for peer %s", pu.peerKey.String())

	defer pu.debouncer.Stop()

	// The heartbeat shares this loop so the stream is only written from one goroutine.
	hb, stopHB := pu.heartbeatTick(ctx)
	defer func() { stopHB() }()
	defer pu.alignKeepAlive()()

	for {
		select {
		// condition when there are some updates
		// todo set the updates channel size to 1
		case update, open := <-pu.updates:
			if pu.appMetrics != nil {
				pu.appMetrics.GRPCMetrics().UpdateChannelQueueLength(len(pu.updates) + 1)
			}

			if !open {
				log.WithContext(ctx).Debugf("updates channel for peer %s was closed", pu.peerKey.String())
				pu.cleanupFunc()
				return nil
			}

			log.WithContext(ctx).Tracef("received an update for peer %s", pu.peerKey.String())
			if pu.debouncer.ProcessUpdate(update) {
				// Send immediately (first update or after quiet period)
				if err := pu.SendUpdate(ctx, update); err != nil {
					log.WithContext(ctx).Debugf("error while sending an update to peer %s: %v", pu.peerKey.String(), err)
					return err
				}
			}

		// Timer expired - quiet period reached, send pending updates if any
		case <-pu.debouncer.TimerChannel():
			pendingUpdates := pu.debouncer.GetPendingUpdates()
			if len(pendingUpdates) == 0 {
				continue
			}
			log.WithContext(ctx).Debugf("sending %d debounced update(s) for peer %s", len(pendingUpdates), pu.peerKey.String())
			for _, pendingUpdate := range pendingUpdates {
				if err := pu.SendUpdate(ctx, pendingUpdate); err != nil {
					log.WithContext(ctx).Debugf("error while sending an update to peer %s: %v", pu.peerKey.String(), err)
					return err
				}
			}

		case <-hb:
			update, moved := pu.nextHeartbeat(ctx, time.Now())
			if err := pu.SendUpdate(ctx, update); err != nil {
				log.WithContext(ctx).Debugf("error while sending a heartbeat to peer %s: %v", pu.peerKey.String(), err)
				return err
			}
			log.WithContext(ctx).Tracef("sent heartbeat to peer %s", pu.peerKey.String())
			if pu.appMetrics != nil {
				pu.appMetrics.GRPCMetrics().AlignedHeartbeat().HeartbeatSent(ctx)
			}
			if moved {
				stopHB()
				hb, stopHB = pu.heartbeatTick(ctx)
			}

		// condition when client <-> server connection has been terminated
		case <-pu.srv.Context().Done():
			// happens when connection drops, e.g. client disconnects
			log.WithContext(ctx).Debugf("stream of peer %s has been closed", pu.peerKey.String())
			pu.cleanupFunc()
			return pu.srv.Context().Err()
		}
	}
}

func (pu *PeerUpdateHandler) SendUpdate(ctx context.Context, update *network_map.UpdateMessage) error {
	key, err := pu.secretsManager.GetWGKey()
	if err != nil {
		pu.cleanupFunc()
		return status.Errorf(codes.Internal, "failed processing update message")
	}

	if stampCertificateChallenges(update.Update.GetChecks(), pu.challenger, pu.peerKey) && pu.onChallengeStamped != nil {
		pu.onChallengeStamped()
	}
	if pu.srvPubKey == "" || pu.srvKey != key {
		pu.srvKey = key
		pu.srvPubKey = key.PublicKey().String()
	}
	encryptedResp, err := pu.encrypter.EncryptMessage(pu.peerKey, key, update.Update)
	if err != nil {
		pu.cleanupFunc()
		return status.Errorf(codes.Internal, "failed processing update message")
	}
	err = pu.srv.Send(&proto.EncryptedMessage{
		WgPubKey: pu.srvPubKey,
		Body:     encryptedResp,
	})
	if err != nil {
		pu.cleanupFunc()
		return status.Errorf(codes.Internal, "failed sending update message")
	}
	log.WithContext(ctx).Tracef("sent an update to peer %s", pu.peerKey.String())
	return nil
}

// alignKeepAlive switches the TCP keepalive of the stream connection to the
// aligned period, so the server sends no probe between two heartbeats. It
// returns the func that restores the stock keepalive. A stock stream, or one
// whose connection the server did not store, keeps the connection as it is.
func (pu *PeerUpdateHandler) alignKeepAlive() (restore func()) {
	if pu.aligned == nil {
		return func() {}
	}
	ka := keepalive.ForStream(pu.srv.Context())
	ka.SetAligned(pu.aligned.answer.Period)
	return ka.Restore
}

// heartbeatUpdate returns the aligned heartbeat message, with the config of a
// newly signed phase when cfg is set. It carries nothing else, so the client
// never hands it to its network map handler.
func heartbeatUpdate(cfg *proto.AlignedHeartbeatConfig) *network_map.UpdateMessage {
	return &network_map.UpdateMessage{Update: &proto.SyncResponse{Heartbeat: &proto.Heartbeat{Config: cfg}}}
}

func (e *streamEncrypter) EncryptMessage(remotePubKey wgtypes.Key, ourPrivateKey wgtypes.Key, message pb.Message) ([]byte, error) {
	if e.cache == nil || e.key != ourPrivateKey {
		e.cache = encryption.NewSharedKeyCache(ourPrivateKey)
		e.key = ourPrivateKey
	}
	return e.cache.EncryptMessage(remotePubKey, message)
}
