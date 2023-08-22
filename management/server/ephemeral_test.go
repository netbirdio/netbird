package server

import (
	"fmt"
	"testing"
	"time"
)

type storeMock struct {
	accounts []*Account
}

func (s storeMock) GetAllAccounts() []*Account {
	return s.accounts
}

func (s storeMock) GetAccount(accountID string) (*Account, error) {
	panic("implement me")
}

func (s storeMock) GetAccountByUser(userID string) (*Account, error) {
	panic("implement me")
}

func (s storeMock) GetAccountByPeerPubKey(peerKey string) (*Account, error) {
	panic("implement me")
}

func (s storeMock) GetAccountByPeerID(peerID string) (*Account, error) {
	panic("implement me")
}

func (s storeMock) GetAccountBySetupKey(setupKey string) (*Account, error) {
	panic("implement me")
}

func (s storeMock) GetAccountByPrivateDomain(domain string) (*Account, error) {
	panic("implement me")
}

func (s storeMock) GetTokenIDByHashedToken(secret string) (string, error) {
	panic("implement me")
}

func (s storeMock) GetUserByTokenID(tokenID string) (*User, error) {
	panic("implement me")
}

func (s storeMock) SaveAccount(account *Account) error {
	panic("implement me")
}

func (s storeMock) DeleteHashedPAT2TokenIDIndex(hashedToken string) error {
	panic("implement me")
}

func (s storeMock) DeleteTokenID2UserIDIndex(tokenID string) error {
	panic("implement me")
}

func (s storeMock) GetInstallationID() string {
	panic("implement me")
}

func (s storeMock) SaveInstallationID(ID string) error {
	panic("implement me")
}

func (s storeMock) AcquireAccountLock(accountID string) func() {
	panic("implement me")
}

func (s storeMock) AcquireGlobalLock() func() {
	panic("implement me")
}

func (s storeMock) SavePeerStatus(accountID, peerID string, status PeerStatus) error {
	panic("implement me")
}

func (s storeMock) Close() error {
	panic("implement me")
}

func TestNewManager(t *testing.T) {
	startTime := time.Now()
	timeNow = func() time.Time {
		return startTime
	}

	store := &storeMock{}
	numberOfPeers := 5
	seedPeers(store, true, numberOfPeers)
	seedPeers(store, false, numberOfPeers)

	tickerPeriod = 300 * time.Millisecond
	mgr := NewEphemeralManager(store)
	mgr.Start()
	if len(mgr.peers) != numberOfPeers {
		t.Errorf("failed to fill well the peer store, expected peers: %d, actual peers: %d", numberOfPeers, len(mgr.peers))
	}

	startTime = startTime.Add(ephemeralLifeTime + 1)

	// ugly way to manipulate internal ticker
	time.Sleep(tickerPeriod + 300*time.Millisecond)

	if len(mgr.peers) != 0 {
		t.Errorf("failed to cleanup ephemeral peers: %d", len(mgr.peers))
	}
}

func seedPeers(store *storeMock, ephemeral bool, numberOfPeers int) {
	for i := 0; i < numberOfPeers; i++ {
		p := &Peer{
			ID:        fmt.Sprintf("%d", i),
			Ephemeral: ephemeral,
		}
		a := newAccountWithId(fmt.Sprintf("account_%d", i), fmt.Sprintf("user_%d", i), "example.com")
		a.Peers[p.ID] = p
		store.accounts = append(store.accounts, a)
	}
}
