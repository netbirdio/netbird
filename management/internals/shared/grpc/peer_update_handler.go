package grpc

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/management/proto"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func PeerUpdateHandlerFactory(
	peerKey wgtypes.Key,
	updates chan *network_map.UpdateMessage,
	secretsManager SecretsManager,
	srv proto.ManagementService_SyncServer,
	cleanupfunc func()) *PeerUpdateHandler {
	return &PeerUpdateHandler{
		peerKey:        peerKey,
		updates:        updates,
		secretsManager: secretsManager,
		srv:            srv,
		encrypter:      encryption.DefaultEncrypter{},
		debouncer:      NewUpdateDebouncer(1000 * time.Millisecond),
		cleanupFunc:    cleanupfunc,
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
	srv            syncSender
	encrypter      encryption.Encrypter
	debouncer      Debouncer
	cleanupFunc    func()
}

//go:generate go tool mockgen -source=./peer_update_handler.go -destination=./sync_sender_mock.go -package=grpc
type syncSender interface {
	Send(*proto.EncryptedMessage) error
	Context() context.Context
}

func (pu *PeerUpdateHandler) HandleUpdates(ctx context.Context) error {
	log.WithContext(ctx).Tracef("starting to handle updates for peer %s", pu.peerKey.String())

	defer pu.debouncer.Stop()

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

	encryptedResp, err := pu.encrypter.EncryptMessage(pu.peerKey, key, update.Update)
	if err != nil {
		pu.cleanupFunc()
		return status.Errorf(codes.Internal, "failed processing update message")
	}
	err = pu.srv.Send(&proto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
		Body:     encryptedResp,
	})
	if err != nil {
		pu.cleanupFunc()
		return status.Errorf(codes.Internal, "failed sending update message")
	}
	log.WithContext(ctx).Tracef("sent an update to peer %s", pu.peerKey.String())
	return nil
}
