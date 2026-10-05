package network_map

import "context"

type PeersUpdateManager interface {
	SendUpdate(ctx context.Context, peerID string, update *UpdateMessage)
	CreateChannel(ctx context.Context, peerID string) chan *UpdateMessage
	CloseChannel(ctx context.Context, peerID string)
	// CloseSessionChannel closes the peer's channel and returns true, unless a channel of
	// another session is registered, in which case it returns false and closes nothing.
	// A nil session owns no channel and succeeds only when none is registered.
	CloseSessionChannel(ctx context.Context, peerID string, session chan *UpdateMessage) bool
	CountStreams() int
	HasChannel(peerID string) bool
	CloseChannels(ctx context.Context, peerIDs []string)
	GetAllConnectedPeers() map[string]struct{}
}
