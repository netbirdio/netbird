package proxy

// PlaygroundPrincipalKind identifies the emulated principal source.
type PlaygroundPrincipalKind string

const (
	// PlaygroundPrincipalPeer resolves a concrete peer and its current owner and groups.
	PlaygroundPrincipalPeer PlaygroundPrincipalKind = "peer"
	// PlaygroundPrincipalGroup uses one synthetic group without a user identity.
	PlaygroundPrincipalGroup PlaygroundPrincipalKind = "group"
)

// AgentNetworkPlaygroundHeader preserves repeated provider-native header values.
type AgentNetworkPlaygroundHeader struct {
	Name   string
	Values []string
}

// AgentNetworkPlaygroundRequest is a trusted command sent from Management to a proxy.
type AgentNetworkPlaygroundRequest struct {
	PrincipalKind PlaygroundPrincipalKind
	PrincipalID   string
	RequestID     string
	AccountID     string
	Domain        string
	UserID        string
	UserEmail     string
	GroupIDs      []string
	GroupNames    []string
	Method        string
	Path          string
	Headers       []AgentNetworkPlaygroundHeader
	Body          []byte
}

// AgentNetworkPlaygroundResponse is the bounded result returned by a proxy.
type AgentNetworkPlaygroundResponse struct {
	RequestID           string
	AccountID           string
	StatusCode          int
	Headers             []AgentNetworkPlaygroundHeader
	Body                []byte
	BodyTruncated       bool
	UserID              string
	UserEmail           string
	GroupIDs            []string
	GroupNames          []string
	PolicyDecision      string
	PolicyReason        string
	ProviderSurface     string
	Model               string
	ResolvedProviderID  string
	AuthorisingGroupIDs []string
	SelectedPolicyID    string
	AttributionGroupID  string
}
