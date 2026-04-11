package server

// AuthRequest is the sideband authorization request sent by the connecting peer
// to the target peer's RDP auth server over the WireGuard tunnel.
type AuthRequest struct {
	JWTToken      string `json:"jwt_token"`
	RequestedUser string `json:"requested_user"`
	ClientPeerIP  string `json:"client_peer_ip"`
	Nonce         string `json:"nonce"`
}

// AuthResponse is the sideband authorization response sent by the target peer
// back to the connecting peer.
type AuthResponse struct {
	Status    string `json:"status"`              // "authorized" or "denied"
	SessionID string `json:"session_id,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"` // unix timestamp
	OSUser    string `json:"os_user,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// PipeRequest is the IPC request from the Credential Provider DLL to the NetBird agent
// via the named pipe.
type PipeRequest struct {
	Action    string `json:"action"`               // "query_pending" or "consume"
	RemoteIP  string `json:"remote_ip"`             // connecting peer's WG IP
	SessionID string `json:"session_id,omitempty"` // for consume action
}

// PipeResponse is the IPC response from the NetBird agent to the Credential Provider DLL.
type PipeResponse struct {
	Found     bool   `json:"found"`
	SessionID string `json:"session_id,omitempty"`
	OSUser    string `json:"os_user,omitempty"`
	Domain    string `json:"domain,omitempty"`
}

const (
	// StatusAuthorized indicates the RDP session was authorized.
	StatusAuthorized = "authorized"
	// StatusDenied indicates the RDP session was denied.
	StatusDenied = "denied"

	// PipeActionQuery queries for a pending session by remote IP.
	PipeActionQuery = "query_pending"
	// PipeActionConsume marks a pending session as consumed.
	PipeActionConsume = "consume"
)
