package types

import (
	"testing"

	"github.com/netbirdio/netbird/management/server/testutil"
)

func TestNetwork_EqualComparesAllFields(t *testing.T) {
	// PublicID is copied from the stored network before comparing.
	testutil.EqualComparesAllFields(t, (*Network).Equal, "PublicID")
}
