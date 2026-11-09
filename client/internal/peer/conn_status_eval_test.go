package peer

import (
	"testing"

	"github.com/netbirdio/netbird/client/internal/peer/guard"
)

func TestEvalConnStatus_ForceRelay(t *testing.T) {
	tests := []struct {
		name string
		in   connStatusInputs
		want guard.ConnStatus
	}{
		{
			name: "force relay, peer uses relay, relay up",
			in: connStatusInputs{
				forceRelay:     true,
				peerUsesRelay:  true,
				relayConnected: true,
			},
			want: guard.ConnStatusConnected,
		},
		{
			name: "force relay, peer uses relay, relay down",
			in: connStatusInputs{
				forceRelay:     true,
				peerUsesRelay:  true,
				relayConnected: false,
			},
			want: guard.ConnStatusDisconnected,
		},
		{
			name: "force relay, relay up but the shared transport reports down",
			in: connStatusInputs{
				forceRelay:              true,
				peerUsesRelay:           true,
				relayConnected:          true,
				relayTransportConnected: false,
				// The ICE inputs are set so that the force-relay return is the only branch
				// that can produce Connected here: without it the peer would fall through to
				// relayUsedAndUp and report PartiallyConnected.
				remoteSupportsICE: true,
				iceWorkerCreated:  true,
			},
			want: guard.ConnStatusConnected,
		},
		{
			name: "force relay, peer does NOT use relay - disconnected forever",
			in: connStatusInputs{
				forceRelay:     true,
				peerUsesRelay:  false,
				relayConnected: true,
			},
			want: guard.ConnStatusDisconnected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalConnStatus(tc.in); got != tc.want {
				t.Fatalf("evalConnStatus = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvalConnStatus_ICEUnavailable(t *testing.T) {
	tests := []struct {
		name string
		in   connStatusInputs
		want guard.ConnStatus
	}{
		{
			name: "remote does not support ICE, peer uses relay, relay up",
			in: connStatusInputs{
				peerUsesRelay:     true,
				relayConnected:    true,
				remoteSupportsICE: false,
				iceWorkerCreated:  true,
			},
			want: guard.ConnStatusConnected,
		},
		{
			name: "remote does not support ICE, peer uses relay, relay down",
			in: connStatusInputs{
				peerUsesRelay:     true,
				relayConnected:    false,
				remoteSupportsICE: false,
				iceWorkerCreated:  true,
			},
			want: guard.ConnStatusDisconnected,
		},
		{
			name: "ICE worker not yet created, relay up",
			in: connStatusInputs{
				peerUsesRelay:     true,
				relayConnected:    true,
				remoteSupportsICE: true,
				iceWorkerCreated:  false,
			},
			want: guard.ConnStatusConnected,
		},
		{
			name: "remote does not support ICE, peer does not use relay",
			in: connStatusInputs{
				peerUsesRelay:     false,
				relayConnected:    false,
				remoteSupportsICE: false,
				iceWorkerCreated:  true,
			},
			want: guard.ConnStatusDisconnected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalConnStatus(tc.in); got != tc.want {
				t.Fatalf("evalConnStatus = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvalConnStatus_FullyAvailable(t *testing.T) {
	base := connStatusInputs{
		remoteSupportsICE: true,
		iceWorkerCreated:  true,
	}

	tests := []struct {
		name    string
		mutator func(*connStatusInputs)
		want    guard.ConnStatus
	}{
		{
			name: "ICE connected, relay connected, peer uses relay",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = true
				in.relayConnected = true
				in.relayTransportConnected = true
				in.iceStatusConnected = true
			},
			want: guard.ConnStatusConnected,
		},
		{
			name: "ICE connected, peer does NOT use relay, shared transport down",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = false
				in.relayConnected = false
				in.relayTransportConnected = false
				in.iceStatusConnected = true
			},
			// A peer that does not rely on relay is unaffected by the shared transport:
			// relayOK is true, so the first arm matches before the transport is considered.
			want: guard.ConnStatusConnected,
		},
		{
			name: "ICE InProgress only, peer does NOT use relay",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = false
				in.iceStatusConnected = false
				in.iceInProgress = true
			},
			want: guard.ConnStatusConnected,
		},
		{
			name: "ICE down, relay up, peer uses relay -> partial",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = true
				in.relayConnected = true
				in.relayTransportConnected = true
				in.iceStatusConnected = false
				in.iceInProgress = false
			},
			want: guard.ConnStatusPartiallyConnected,
		},
		{
			name: "ICE down, peer does NOT use relay -> disconnected",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = false
				in.relayConnected = false
				in.iceStatusConnected = false
				in.iceInProgress = false
			},
			want: guard.ConnStatusDisconnected,
		},
		{
			name: "ICE connected, relay down for this peer but the shared transport is up -> disconnected",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = true
				in.relayConnected = false
				in.relayTransportConnected = true
				in.iceStatusConnected = true
			},
			// The transport is fine, so the peer itself is unreachable over relay: it may have
			// moved to another server, and only an offer carries its new relay address.
			want: guard.ConnStatusDisconnected,
		},
		{
			name: "ICE connected, the shared relay transport is down -> partial",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = true
				in.relayConnected = false
				in.relayTransportConnected = false
				in.iceStatusConnected = true
			},
			// ICE carries the traffic and the relay transport is restored by the relay client's
			// own guard, not by offers, so this must not trigger the aggressive retry.
			want: guard.ConnStatusPartiallyConnected,
		},
		{
			name: "ICE only negotiating while the shared relay transport is down -> disconnected",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = true
				in.relayConnected = false
				in.relayTransportConnected = false
				in.iceStatusConnected = false
				in.iceInProgress = true
			},
			// A negotiation in flight is not a working transport, so this peer has no path at
			// all and must keep the aggressive retry. Calling it partially connected spends the
			// ICE retry budget and parks the guard on the hourly ticker, and nothing wakes it
			// when the negotiation then fails: onICEStateDisconnected is only reached once ICE
			// has reached Connected (worker_ice.go onConnectionStateChange).
			want: guard.ConnStatusDisconnected,
		},
		{
			name: "ICE down and the shared relay transport is down -> disconnected",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = true
				in.relayConnected = false
				in.relayTransportConnected = false
				in.iceStatusConnected = false
				in.iceInProgress = false
			},
			want: guard.ConnStatusDisconnected,
		},
		{
			name: "ICE down, relay up but peer does not use relay -> disconnected",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = false
				in.relayConnected = true // not actually used since peer doesn't rely on it
				in.iceStatusConnected = false
				in.iceInProgress = false
			},
			want: guard.ConnStatusDisconnected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.mutator(&in)
			if got := evalConnStatus(in); got != tc.want {
				t.Fatalf("evalConnStatus = %v, want %v (inputs: %+v)", got, tc.want, in)
			}
		})
	}
}
