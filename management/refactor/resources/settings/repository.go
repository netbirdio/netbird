package settings

import "github.com/netbirdio/netbird/management/refactor/resources/settings/types"

type Repository interface {
	FindSettings(accountID string) (types.Settings, error)
}
