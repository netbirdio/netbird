package settings

type Repository interface {
	FindSettings(accountID string) (Settings, error)
}
