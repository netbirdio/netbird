package peer_connections

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/peer_connections"
	"github.com/netbirdio/netbird/shared/auth"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

type fakeAM struct {
	peers      map[string]*nbpeer.Peer // peerID → Peer
	peersByKey map[string]*nbpeer.Peer // pubkey → Peer
	allowedAcc string
	dnsDomain  string
}

func (a *fakeAM) GetPeer(_ context.Context, accountID, peerID, _ string) (*nbpeer.Peer, error) {
	if a.allowedAcc != "" && a.allowedAcc != accountID {
		return nil, errors.New("not found")
	}
	p, ok := a.peers[peerID]
	if !ok {
		return nil, errors.New("not found")
	}
	return p, nil
}

func (a *fakeAM) GetPeerByPubKey(_ context.Context, _, pubKey string) (*nbpeer.Peer, error) {
	p, ok := a.peersByKey[pubKey]
	if !ok {
		return nil, errors.New("not found")
	}
	return p, nil
}

func (a *fakeAM) GetDNSDomain(_ context.Context, _ string) string { return a.dnsDomain }

type fakeRouter struct{ calls int }

func (f *fakeRouter) Request(_ string, _ uint64) bool { f.calls++; return true }

func authedReq(method, target, accountID, userID string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	return nbcontext.SetUserAuthInRequest(r, auth.UserAuth{AccountId: accountID, UserId: userID})
}

func TestHandler_GetPeerConnections_Returns200WithCachedData(t *testing.T) {
	store := peer_connections.NewMemoryStore(time.Hour)
	store.Put("PUBKEY-A", &mgmProto.PeerConnectionMap{
		Seq:          1,
		FullSnapshot: true,
		Entries:      []*mgmProto.PeerConnectionEntry{{RemotePubkey: "PUBKEY-B", ConnType: mgmProto.ConnType_CONN_TYPE_P2P, LatencyMs: 12}},
	})
	am := &fakeAM{
		peers:      map[string]*nbpeer.Peer{"peerA-id": {ID: "peerA-id", Key: "PUBKEY-A", AccountID: "acc1"}},
		peersByKey: map[string]*nbpeer.Peer{"PUBKEY-B": {ID: "peerB-id", Key: "PUBKEY-B", AccountID: "acc1"}},
		dnsDomain:  "test.example",
	}
	h := NewHandler(store, am, nil)

	r := authedReq("GET", "/api/peers/peerA-id/connections", "acc1", "user1")
	r = mux.SetURLVars(r, map[string]string{"peerId": "peerA-id"})
	w := httptest.NewRecorder()
	h.GetPeerConnections(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PUBKEY-B") {
		t.Errorf("want PUBKEY-B in body, got %s", w.Body.String())
	}
}

func TestHandler_GetPeerConnections_401WithoutAuth(t *testing.T) {
	h := NewHandler(peer_connections.NewMemoryStore(time.Hour), &fakeAM{}, nil)
	r := httptest.NewRequest("GET", "/api/peers/peerA-id/connections", nil)
	r = mux.SetURLVars(r, map[string]string{"peerId": "peerA-id"})
	w := httptest.NewRecorder()
	h.GetPeerConnections(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestHandler_GetPeerConnections_404WhenPeerNotInAccount(t *testing.T) {
	store := peer_connections.NewMemoryStore(time.Hour)
	am := &fakeAM{
		peers:      map[string]*nbpeer.Peer{"peerA-id": {ID: "peerA-id", Key: "PUBKEY-A", AccountID: "acc1"}},
		allowedAcc: "acc1",
	}
	h := NewHandler(store, am, nil)
	// Authed as different account.
	r := authedReq("GET", "/api/peers/peerA-id/connections", "acc2", "user1")
	r = mux.SetURLVars(r, map[string]string{"peerId": "peerA-id"})
	w := httptest.NewRecorder()
	h.GetPeerConnections(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestHandler_PostRefresh_Returns202WithToken(t *testing.T) {
	store := peer_connections.NewMemoryStore(time.Hour)
	am := &fakeAM{
		peers: map[string]*nbpeer.Peer{"peerA-id": {ID: "peerA-id", Key: "PUBKEY-A", AccountID: "acc1"}},
	}
	router := &fakeRouter{}
	h := NewHandler(store, am, router)
	r := authedReq("POST", "/api/peers/peerA-id/connections/refresh", "acc1", "user1")
	r = mux.SetURLVars(r, map[string]string{"peerId": "peerA-id"})
	w := httptest.NewRecorder()
	h.PostRefresh(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d", w.Code)
	}
	var body refreshResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.RefreshToken == 0 {
		t.Error("want non-zero refresh_token")
	}
	if router.calls != 1 {
		t.Errorf("want 1 SnapshotRequester call, got %d", router.calls)
	}
}
