package settings

type repository interface {
	FindSettings(accountID string) (Settings, error)
}
