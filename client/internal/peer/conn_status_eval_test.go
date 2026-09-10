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
				in.iceStatusConnecting = true
			},
			want: guard.ConnStatusConnected,
		},
		{
			name: "ICE connected, peer does NOT use relay",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = false
				in.relayConnected = false
				in.iceStatusConnecting = true
			},
			want: guard.ConnStatusConnected,
		},
		{
			name: "ICE InProgress only, peer does NOT use relay",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = false
				in.iceStatusConnecting = false
				in.iceInProgress = true
			},
			want: guard.ConnStatusConnected,
		},
		{
			name: "ICE down, relay up, peer uses relay -> partial",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = true
				in.relayConnected = true
				in.iceStatusConnecting = false
				in.iceInProgress = false
			},
			want: guard.ConnStatusPartiallyConnected,
		},
		{
			name: "ICE down, peer does NOT use relay -> disconnected",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = false
				in.relayConnected = false
				in.iceStatusConnecting = false
				in.iceInProgress = false
			},
			want: guard.ConnStatusDisconnected,
		},
		{
			name: "ICE up, relay down for this peer but the shared transport is up -> disconnected",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = true
				in.relayConnected = false
				in.relayTransportConnected = true
				in.iceStatusConnecting = true
			},
			// The transport is fine, so the peer itself is unreachable over relay: it may have
			// moved to another server, and only an offer carries its new relay address.
			want: guard.ConnStatusDisconnected,
		},
		{
			name: "ICE up, the shared relay transport is down -> partial",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = true
				in.relayConnected = false
				in.relayTransportConnected = false
				in.iceStatusConnecting = true
			},
			// ICE carries the traffic and the relay transport is restored by the relay client's
			// own guard, not by offers, so this must not trigger the aggressive retry.
			want: guard.ConnStatusPartiallyConnected,
		},
		{
			name: "ICE down and the shared relay transport is down -> disconnected",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = true
				in.relayConnected = false
				in.relayTransportConnected = false
				in.iceStatusConnecting = false
				in.iceInProgress = false
			},
			want: guard.ConnStatusDisconnected,
		},
		{
			name: "ICE down, relay up but peer does not use relay -> disconnected",
			mutator: func(in *connStatusInputs) {
				in.peerUsesRelay = false
				in.relayConnected = true // not actually used since peer doesn't rely on it
				in.iceStatusConnecting = false
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
