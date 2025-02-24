package configurer

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var ipcFixture = `
private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a
listen_port=12912
public_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33
preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52
allowed_ip=192.168.4.4/32
endpoint=[abcd:23::33%2]:51820
public_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376
tx_bytes=38333
rx_bytes=2224
allowed_ip=192.168.4.6/32
persistent_keepalive_interval=111
endpoint=182.122.22.19:3233
public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58
endpoint=5.152.198.39:51820
allowed_ip=192.168.4.10/32
allowed_ip=192.168.4.11/32
tx_bytes=1212111
rx_bytes=1929999999
protocol_version=1
errno=0

`

func Test_Transfer(t *testing.T) {
	stats, err := parseTransfers(ipcFixture)
	if err != nil {
		t.Fatal(err)
	}

	if len(stats) != 3 {
		t.Fatalf("expected 2 stats, got %d", len(stats))
	}
}

func Test_findPeerInfo(t *testing.T) {
	tests := []struct {
		name       string
		peerKey    string
		searchKeys []string
		want       map[string]string
		wantErr    bool
	}{
		{
			name:       "single",
			peerKey:    "58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376",
			searchKeys: []string{"tx_bytes"},
			want: map[string]string{
				"tx_bytes": "38333",
			},
			wantErr: false,
		},
		{
			name:       "multiple",
			peerKey:    "58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376",
			searchKeys: []string{"tx_bytes", "rx_bytes"},
			want: map[string]string{
				"tx_bytes": "38333",
				"rx_bytes": "2224",
			},
			wantErr: false,
		},
		{
			name:       "lastpeer",
			peerKey:    "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58",
			searchKeys: []string{"tx_bytes", "rx_bytes"},
			want: map[string]string{
				"tx_bytes": "1212111",
				"rx_bytes": "1929999999",
			},
			wantErr: false,
		},
		{
			name:       "peer not found",
			peerKey:    "1111111111111111111111111111111111111111111111111111111111111111",
			searchKeys: nil,
			want:       nil,
			wantErr:    true,
		},
		{
			name:       "key not found",
			peerKey:    "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58",
			searchKeys: []string{"tx_bytes", "unknown_key"},
			want: map[string]string{
				"tx_bytes": "1212111",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := hex.DecodeString(tt.peerKey)
			require.NoError(t, err)

			key, err := wgtypes.NewKey(res)
			require.NoError(t, err)

			got, err := findPeerInfo(ipcFixture, key.String(), tt.searchKeys)
			assert.Equalf(t, tt.wantErr, err != nil, fmt.Sprintf("findPeerInfo(%v, %v, %v)", ipcFixture, key.String(), tt.searchKeys))
			assert.Equalf(t, tt.want, got, "findPeerInfo(%v, %v, %v)", ipcFixture, key.String(), tt.searchKeys)
		})
	}
}
