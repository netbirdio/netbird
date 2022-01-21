package peer

import (
	"context"
	"github.com/pion/ice/v2"
	"io"
)

// ICEAgent represents an ICE agent
type ICEAgent interface {
	io.Closer
	AddRemoteCandidate(candidate ice.Candidate) error
	GatherCandidates() error
	Dial(ctx context.Context, ufrag string, pwd string) (*ice.Conn, error)
	Accept(ctx context.Context, ufrag string, pwd string) (*ice.Conn, error)
	OnCandidate(f func(ice.Candidate)) error
	OnConnectionStateChange(f func(ice.ConnectionState)) error
	OnSelectedCandidatePairChange(f func(ice.Candidate, ice.Candidate)) error
	GetLocalUserCredentials() (frag string, pwd string, err error)
}
