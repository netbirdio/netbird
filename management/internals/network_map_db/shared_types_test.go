package networkmapdb

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestRecordTypeAndRdata(t *testing.T) {
	var tests = []struct {
		recordType         string
		expectedRecordType int
		rdata              string
		expectedRdata      string
		expectedErr        error
	}{
		{recordType: "A", expectedRecordType: 1, rdata: "test.com", expectedRdata: "test.com", expectedErr: nil},
		{recordType: "AAAA", expectedRecordType: 28, rdata: "test.com", expectedRdata: "test.com", expectedErr: nil},
		{recordType: "CNAME", expectedRecordType: 5, rdata: "test.com", expectedRdata: "test.com.", expectedErr: nil},
		{recordType: "CNAME", expectedRecordType: 5, rdata: "test.com.", expectedRdata: "test.com.", expectedErr: nil},
		{recordType: "TypeMX", expectedErr: ErrDnsUnsupportedRecordType},
	}

	for _, tt := range tests {
		t.Run(tt.recordType, func(t *testing.T) {
			recordType, rdata, err := RecordTypeAndRdata(tt.recordType, tt.rdata)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, ErrDnsUnsupportedRecordType)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, recordType, tt.expectedRecordType)
			assert.Equal(t, rdata, tt.expectedRdata)
		})
	}
}

// TestConvertToNmdataPeers_CarriesTheVerifiedCertificates: the certificate posture check is
// evaluated on the chains stored in the peer meta, so a peer loaded through this path with
// its certificates dropped would silently fail every certificate check.
func TestConvertToNmdataPeers_CarriesTheVerifiedCertificates(t *testing.T) {
	peers, _, err := ConvertToNmdataPeers([]Peer{
		{MetaCertificates: []byte(`["-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n","chain-2"]`)},
		{},
	})

	require.NoError(t, err)
	require.Len(t, peers, 2)
	assert.Equal(t, []string{"-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n", "chain-2"}, peers[0].Meta.Certificates)
	assert.Empty(t, peers[1].Meta.Certificates, "a peer that proved nothing has no certificates")
}

func TestConvertToNmdataPeers_RejectsMalformedCertificates(t *testing.T) {
	_, _, err := ConvertToNmdataPeers([]Peer{{MetaCertificates: []byte(`{"not":"a list"}`)}})

	assert.Error(t, err, "a stored value that is not a list of chains must not load as no certificates")
}

// TestConvertToNmdataPeers_StaleEmbeddedProxyIsNotACandidate: a management instance that
// stops without releasing its peers leaves their connection rows behind. An embedded
// proxy peer connected through such an instance must not become a private service DNS
// target, or clients resolve the service to a tunnel IP that no longer answers.
func TestConvertToNmdataPeers_StaleEmbeddedProxyIsNotACandidate(t *testing.T) {
	embedded := func(id string, session sql.NullInt64, instanceLastSeen time.Time) Peer {
		return Peer{
			ID:                   id,
			PeerSessionStartedAt: session,
			InstanceLastSeen:     sql.NullTime{Time: instanceLastSeen, Valid: !instanceLastSeen.IsZero()},
			ProxyMetaEmbedded:    sql.NullBool{Bool: true, Valid: true},
			ProxyMetaCluster:     sql.NullString{String: "cluster", Valid: true},
		}
	}
	session := sql.NullInt64{Int64: 1, Valid: true}

	peers, clusterToPeers, err := ConvertToNmdataPeers([]Peer{
		embedded("live", session, time.Now().Add(-time.Minute)),
		embedded("stale", session, time.Now().Add(-nbpeer.StaleAfter-time.Minute)),
		embedded("no-instance", session, time.Time{}),
		embedded("no-row", sql.NullInt64{}, time.Time{}),
	})

	require.NoError(t, err)
	require.Len(t, peers, 4)
	assert.True(t, peers[0].Connected)
	assert.False(t, peers[1].Connected, "a peer on an instance silent for longer than StaleAfter must read as disconnected")
	assert.False(t, peers[2].Connected, "a peer on a missing instance must read as disconnected")
	assert.False(t, peers[3].Connected, "a peer without a connection row must read as disconnected")
	require.Len(t, clusterToPeers["cluster"], 1)
	assert.Equal(t, "live", clusterToPeers["cluster"][0].ID)
}
