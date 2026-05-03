package peer_connections

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/peer_connections"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// AccountManager is the slice of the existing AccountManager interface
// this handler needs. Phase 3.7i of #5989.
type AccountManager interface {
	GetPeer(ctx context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error)
	GetDNSDomain(ctx context.Context, accountID string) string
	GetPeerByPubKey(ctx context.Context, accountID, pubKey string) (*nbpeer.Peer, error)
}

// SnapshotRequester triggers a SnapshotRequest on the peer's active
// Sync server-stream. Phase 3.7i of #5989.
type SnapshotRequester interface {
	Request(peerPubKey string, nonce uint64) bool
}

type Handler struct {
	store   peer_connections.Store
	account AccountManager
	router  SnapshotRequester
	nonce   atomic.Uint64
}

func NewHandler(store peer_connections.Store, account AccountManager, router SnapshotRequester) *Handler {
	return &Handler{store: store, account: account, router: router}
}

type apiEntry struct {
	RemotePubkey  string `json:"remote_pubkey"`
	RemoteFQDN    string `json:"remote_fqdn,omitempty"`
	ConnType      string `json:"conn_type"`
	LastHandshake string `json:"last_handshake,omitempty"`
	LatencyMs     uint32 `json:"latency_ms,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	RelayServer   string `json:"relay_server,omitempty"`
	RxBytes       uint64 `json:"rx_bytes,omitempty"`
	TxBytes       uint64 `json:"tx_bytes,omitempty"`
}

type apiResponse struct {
	PeerPubkey   string     `json:"peer_pubkey"`
	Seq          uint64     `json:"seq"`
	FullSnapshot bool       `json:"full_snapshot"`
	InResponseTo uint64     `json:"in_response_to_nonce,omitempty"`
	Entries      []apiEntry `json:"entries"`
}

type refreshResponse struct {
	RefreshToken uint64       `json:"refresh_token"`
	CachedMap    *apiResponse `json:"cached_map,omitempty"`
	// Dispatched is true when the snapshot request was actually delivered
	// to an active Sync stream for this peer. False means the peer has
	// no live stream (offline / between connections / older daemon
	// without snapshot-request support) and the caller can decide whether
	// to retry or fall back to the cached map.
	Dispatched bool `json:"dispatched"`
}

// GetPeerConnections handles GET /api/peers/{peerId}/connections.
// 401 missing/invalid auth, 404 peer not found, 200 with body.
// ?since=N blocks up to 5 s for fresh data.
func (h *Handler) GetPeerConnections(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	peerID := mux.Vars(r)["peerId"]
	peer, err := h.account.GetPeer(r.Context(), userAuth.AccountId, peerID, userAuth.UserId)
	if err != nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	pubkey := peer.Key
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)

	var (
		m  *mgmProto.PeerConnectionMap
		ok bool
	)
	if since > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			m, ok = h.store.GetWithNonceCheck(pubkey, since)
			if ok {
				break
			}
			select {
			case <-ctx.Done():
				m, ok = h.store.Get(pubkey)
				goto done
			case <-ticker.C:
			}
		}
	} else {
		m, ok = h.store.Get(pubkey)
	}
done:
	if !ok {
		http.Error(w, "no connection data yet for this peer", http.StatusNotFound)
		return
	}

	dnsDomain := h.account.GetDNSDomain(r.Context(), userAuth.AccountId)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.buildResponse(r.Context(), userAuth.AccountId, dnsDomain, pubkey, m))
}

// PostRefresh handles POST /api/peers/{peerId}/connections/refresh.
func (h *Handler) PostRefresh(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	peerID := mux.Vars(r)["peerId"]
	peer, err := h.account.GetPeer(r.Context(), userAuth.AccountId, peerID, userAuth.UserId)
	if err != nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	pubkey := peer.Key
	nonce := h.nonce.Add(1)
	dispatched := false
	if h.router != nil {
		dispatched = h.router.Request(pubkey, nonce)
	}

	dnsDomain := h.account.GetDNSDomain(r.Context(), userAuth.AccountId)
	resp := refreshResponse{RefreshToken: nonce, Dispatched: dispatched}
	if cached, ok := h.store.Get(pubkey); ok {
		ar := h.buildResponse(r.Context(), userAuth.AccountId, dnsDomain, pubkey, cached)
		resp.CachedMap = &ar
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) buildResponse(ctx context.Context, accountID, dnsDomain, pubkey string, m *mgmProto.PeerConnectionMap) apiResponse {
	resp := apiResponse{
		PeerPubkey:   pubkey,
		Seq:          m.GetSeq(),
		FullSnapshot: m.GetFullSnapshot(),
		InResponseTo: m.GetInResponseToNonce(),
		Entries:      make([]apiEntry, 0, len(m.GetEntries())),
	}
	for _, e := range m.GetEntries() {
		entry := apiEntry{
			RemotePubkey: e.GetRemotePubkey(),
			ConnType:     connTypeToStr(e.GetConnType()),
			LatencyMs:    e.GetLatencyMs(),
			Endpoint:     e.GetEndpoint(),
			RelayServer:  e.GetRelayServer(),
			RxBytes:      e.GetRxBytes(),
			TxBytes:      e.GetTxBytes(),
		}
		if hs := e.GetLastHandshake(); hs != nil && hs.IsValid() {
			entry.LastHandshake = hs.AsTime().Format(time.RFC3339)
		}
		// Enrich remote_fqdn via account-peer lookup (best-effort).
		if rPeer, err := h.account.GetPeerByPubKey(ctx, accountID, e.GetRemotePubkey()); err == nil && rPeer != nil {
			entry.RemoteFQDN = rPeer.FQDN(dnsDomain)
		}
		resp.Entries = append(resp.Entries, entry)
	}
	return resp
}

func connTypeToStr(ct mgmProto.ConnType) string {
	switch ct {
	case mgmProto.ConnType_CONN_TYPE_P2P:
		return "p2p"
	case mgmProto.ConnType_CONN_TYPE_RELAYED:
		return "relayed"
	case mgmProto.ConnType_CONN_TYPE_CONNECTING:
		return "connecting"
	case mgmProto.ConnType_CONN_TYPE_IDLE:
		return "idle"
	default:
		return "unspecified"
	}
}
