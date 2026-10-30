package manager_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/shared/management/domain"
)

func TestNewCountrySet(t *testing.T) {
	set := manager.NewCountrySet([]string{"US", "CA"})

	assert.Equal(t, set, manager.NewCountrySet([]string{"CA", "US"}), "the order of the countries must not matter")
	assert.NotEqual(t, set, manager.NewCountrySet([]string{"US"}), "different countries need different sets")
	assert.NotEqual(t, manager.NewCountrySet([]string{"US"}).HashedName(), manager.NewDomainSet(domain.List{"US"}).HashedName(),
		"a country set must not share its name with a domain set")
	assert.Equal(t, "countries: CA, US", set.Comment())
}
