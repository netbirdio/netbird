package peer

import "context"

type Guard interface {
	Start(ctx context.Context, eventCallback func())
	SetRelayedConnDisconnected()
	SetICEConnDisconnected()
	FailedToSendOffer()
}
