package accounts

type AccountRepository interface {
	findAccountByID(accountID string) (Account, error)
}
