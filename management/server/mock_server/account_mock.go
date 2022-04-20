package mock_server

import (
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MockAccountManager struct {
	GetOrCreateAccountByUserFunc          func(userId, domain string) (*server.Account, error)
	GetAccountByUserFunc                  func(userId string) (*server.Account, error)
	AddSetupKeyFunc                       func(accountId string, keyName string, keyType server.SetupKeyType, expiresIn *util.Duration) (*server.SetupKey, error)
	RevokeSetupKeyFunc                    func(accountId string, keyId string) (*server.SetupKey, error)
	RenameSetupKeyFunc                    func(accountId string, keyId string, newName string) (*server.SetupKey, error)
	GetAccountByIdFunc                    func(accountId string) (*server.Account, error)
	GetAccountByUserOrAccountIdFunc       func(userId, accountId, domain string) (*server.Account, error)
	GetAccountWithAuthorizationClaimsFunc func(claims jwtclaims.AuthorizationClaims) (*server.Account, error)
	AccountExistsFunc                     func(accountId string) (*bool, error)
	AddAccountFunc                        func(accountId, userId, domain string) (*server.Account, error)
	GetPeerFunc                           func(peerKey string) (*server.Peer, error)
	MarkPeerConnectedFunc                 func(peerKey string, connected bool) error
	UpdatePeerAttrsFunc                   func(accountId string, peerKey string, newName string, newTags []string) (*server.Peer, error)
	DeletePeerFunc                        func(accountId string, peerKey string) (*server.Peer, error)
	GetPeerByIPFunc                       func(accountId string, peerIP string) (*server.Peer, error)
	GetNetworkMapFunc                     func(peerKey string) (*server.NetworkMap, error)
	AddPeerFunc                           func(setupKey string, peer *server.Peer) (*server.Peer, error)
}

func (am *MockAccountManager) GetOrCreateAccountByUser(
	userId, domain string,
) (*server.Account, error) {
	if am.GetOrCreateAccountByUserFunc != nil {
		return am.GetOrCreateAccountByUserFunc(userId, domain)
	}
	return nil, status.Errorf(
		codes.Unimplemented,
		"method GetOrCreateAccountByUser not implemented",
	)
}

func (am *MockAccountManager) GetAccountByUser(userId string) (*server.Account, error) {
	if am.GetAccountByUserFunc != nil {
		return am.GetAccountByUserFunc(userId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountByUser not implemented")
}

func (am *MockAccountManager) AddSetupKey(
	accountId string,
	keyName string,
	keyType server.SetupKeyType,
	expiresIn *util.Duration,
) (*server.SetupKey, error) {
	if am.AddSetupKeyFunc != nil {
		return am.AddSetupKeyFunc(accountId, keyName, keyType, expiresIn)
	}
	return nil, status.Errorf(codes.Unimplemented, "method AddSetupKey not implemented")
}

func (am *MockAccountManager) RevokeSetupKey(
	accountId string,
	keyId string,
) (*server.SetupKey, error) {
	if am.RevokeSetupKeyFunc != nil {
		return am.RevokeSetupKeyFunc(accountId, keyId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method RevokeSetupKey not implemented")
}

func (am *MockAccountManager) RenameSetupKey(
	accountId string,
	keyId string,
	newName string,
) (*server.SetupKey, error) {
	if am.RenameSetupKeyFunc != nil {
		return am.RenameSetupKeyFunc(accountId, keyId, newName)
	}
	return nil, status.Errorf(codes.Unimplemented, "method RenameSetupKey not implemented")
}

func (am *MockAccountManager) GetAccountById(accountId string) (*server.Account, error) {
	if am.GetAccountByIdFunc != nil {
		return am.GetAccountByIdFunc(accountId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetAccountById not implemented")
}

func (am *MockAccountManager) GetAccountByUserOrAccountId(
	userId, accountId, domain string,
) (*server.Account, error) {
	if am.GetAccountByUserOrAccountIdFunc != nil {
		return am.GetAccountByUserOrAccountIdFunc(userId, accountId, domain)
	}
	return nil, status.Errorf(
		codes.Unimplemented,
		"method GetAccountByUserOrAccountId not implemented",
	)
}

func (am *MockAccountManager) GetAccountWithAuthorizationClaims(
	claims jwtclaims.AuthorizationClaims,
) (*server.Account, error) {
	if am.GetAccountWithAuthorizationClaimsFunc != nil {
		return am.GetAccountWithAuthorizationClaimsFunc(claims)
	}
	return nil, status.Errorf(
		codes.Unimplemented,
		"method GetAccountWithAuthorizationClaims not implemented",
	)
}

func (am *MockAccountManager) AccountExists(accountId string) (*bool, error) {
	if am.AccountExistsFunc != nil {
		return am.AccountExistsFunc(accountId)
	}
	return nil, status.Errorf(codes.Unimplemented, "method AccountExists not implemented")
}

func (am *MockAccountManager) AddAccount(
	accountId, userId, domain string,
) (*server.Account, error) {
	if am.AddAccountFunc != nil {
		return am.AddAccountFunc(accountId, userId, domain)
	}
	return nil, status.Errorf(codes.Unimplemented, "method AddAccount not implemented")
}

func (am *MockAccountManager) GetPeer(peerKey string) (*server.Peer, error) {
	if am.GetPeerFunc != nil {
		return am.GetPeerFunc(peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeer not implemented")
}

func (am *MockAccountManager) MarkPeerConnected(peerKey string, connected bool) error {
	if am.MarkPeerConnectedFunc != nil {
		return am.MarkPeerConnectedFunc(peerKey, connected)
	}
	return status.Errorf(codes.Unimplemented, "method MarkPeerConnected not implemented")
}

func (am *MockAccountManager) UpdatePeerAttrs(
	accountId string,
	peerKey string,
	newName string,
	newTags []string,
) (*server.Peer, error) {
	if am.UpdatePeerAttrsFunc != nil {
		return am.UpdatePeerAttrsFunc(accountId, peerKey, newName, newTags)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePeerAttrs not implemented")
}

func (am *MockAccountManager) DeletePeer(accountId string, peerKey string) (*server.Peer, error) {
	if am.DeletePeerFunc != nil {
		return am.DeletePeerFunc(accountId, peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method DeletePeer not implemented")
}

func (am *MockAccountManager) GetPeerByIP(accountId string, peerIP string) (*server.Peer, error) {
	if am.GetPeerByIPFunc != nil {
		return am.GetPeerByIPFunc(accountId, peerIP)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetPeerByIP not implemented")
}

func (am *MockAccountManager) GetNetworkMap(peerKey string) (*server.NetworkMap, error) {
	if am.GetNetworkMapFunc != nil {
		return am.GetNetworkMapFunc(peerKey)
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetNetworkMap not implemented")
}

func (am *MockAccountManager) AddPeer(setupKey string, peer *server.Peer) (*server.Peer, error) {
	if am.AddPeerFunc != nil {
		return am.AddPeerFunc(setupKey, peer)
	}
	return nil, status.Errorf(codes.Unimplemented, "method AddPeer not implemented")
}
