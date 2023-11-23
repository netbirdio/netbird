package accounts

type AccountManager interface {
	GetAccount(accountID string) (Account, error)
	GetDNSDomain() string
}

type DefaultAccountManager struct {
	repository AccountRepository

	// dnsDomain is used for peer resolution. This is appended to the peer's name
	dnsDomain string
}

func (am *DefaultAccountManager) GetAccount(accountID string) (Account, error) {
	return am.repository.findAccountByID(accountID)
}

// GetDNSDomain returns the configured dnsDomain
func (am *DefaultAccountManager) GetDNSDomain() string {
	return am.dnsDomain
}
