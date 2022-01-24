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

type iceAgentMock struct {
	CloseFunc                         func() error
	AddRemoteCandidateFunc            func(candidate ice.Candidate) error
	GatherCandidatesFunc              func() error
	DialFunc                          func(ctx context.Context, ufrag string, pwd string) (*ice.Conn, error)
	AcceptFunc                        func(ctx context.Context, ufrag string, pwd string) (*ice.Conn, error)
	OnCandidateFunc                   func(f func(ice.Candidate)) error
	OnConnectionStateChangeFunc       func(f func(ice.ConnectionState)) error
	OnSelectedCandidatePairChangeFunc func(f func(ice.Candidate, ice.Candidate)) error
	GetLocalUserCredentialsFunc       func() (frag string, pwd string, err error)
}

func (m *iceAgentMock) Close() error {
	if m.CloseFunc == nil {
		return nil
	}
	return m.CloseFunc()
}

func (m *iceAgentMock) AddRemoteCandidate(candidate ice.Candidate) error {
	if m.AddRemoteCandidateFunc == nil {
		return nil
	}
	return m.AddRemoteCandidateFunc(candidate)
}

func (m *iceAgentMock) GatherCandidates() error {
	if m.GatherCandidatesFunc == nil {
		return nil
	}
	return m.GatherCandidatesFunc()
}

func (m *iceAgentMock) Dial(ctx context.Context, ufrag string, pwd string) (*ice.Conn, error) {
	if m.DialFunc == nil {
		return nil, nil
	}
	return m.DialFunc(ctx, ufrag, pwd)
}

func (m *iceAgentMock) Accept(ctx context.Context, ufrag string, pwd string) (*ice.Conn, error) {
	if m.AcceptFunc == nil {
		return nil, nil
	}
	return m.AcceptFunc(ctx, ufrag, pwd)
}

func (m *iceAgentMock) OnCandidate(f func(ice.Candidate)) error {
	if m.OnCandidateFunc == nil {
		return nil
	}
	return m.OnCandidateFunc(f)
}

func (m *iceAgentMock) OnSelectedCandidatePairChange(f func(ice.Candidate, ice.Candidate)) error {
	if m.OnSelectedCandidatePairChangeFunc == nil {
		return nil
	}
	return m.OnSelectedCandidatePairChangeFunc(f)
}

func (m *iceAgentMock) OnConnectionStateChange(f func(state ice.ConnectionState)) error {
	if m.OnConnectionStateChangeFunc == nil {
		return nil
	}
	return m.OnConnectionStateChangeFunc(f)
}

func (m *iceAgentMock) GetLocalUserCredentials() (frag string, pwd string, err error) {
	if m.GetLocalUserCredentialsFunc == nil {
		return "", "", nil
	}
	return m.GetLocalUserCredentialsFunc()
}
