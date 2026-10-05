package testing_tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// GetDB extracts the *gorm.DB from a store.Store (must be *SqlStore).
func GetDB(t *testing.T, s store.Store) *gorm.DB {
	t.Helper()
	sqlStore, ok := s.(*store.SqlStore)
	require.True(t, ok, "Store is not a *SqlStore, cannot get gorm.DB")
	return sqlStore.GetDB()
}

// VerifyGroupInDB reads a group directly from the DB and returns it.
func VerifyGroupInDB(t *testing.T, db *gorm.DB, groupID string) *types.Group {
	t.Helper()
	var group types.Group
	err := db.Where("id = ? AND account_id = ?", groupID, TestAccountId).First(&group).Error
	require.NoError(t, err, "Expected group %s to exist in DB", groupID)
	return &group
}

// VerifyGroupNotInDB verifies that a group does not exist in the DB.
func VerifyGroupNotInDB(t *testing.T, db *gorm.DB, groupID string) {
	t.Helper()
	var count int64
	db.Model(&types.Group{}).Where("id = ? AND account_id = ?", groupID, TestAccountId).Count(&count)
	assert.Equal(t, int64(0), count, "Expected group %s to NOT exist in DB", groupID)
}

// VerifyPolicyInDB reads a policy directly from the DB and returns it.
func VerifyPolicyInDB(t *testing.T, db *gorm.DB, policyID string) *types.Policy {
	t.Helper()
	var policy types.Policy
	err := db.Preload("Rules").Where("id = ? AND account_id = ?", policyID, TestAccountId).First(&policy).Error
	require.NoError(t, err, "Expected policy %s to exist in DB", policyID)
	return &policy
}

// VerifyPolicyNotInDB verifies that a policy does not exist in the DB.
func VerifyPolicyNotInDB(t *testing.T, db *gorm.DB, policyID string) {
	t.Helper()
	var count int64
	db.Model(&types.Policy{}).Where("id = ? AND account_id = ?", policyID, TestAccountId).Count(&count)
	assert.Equal(t, int64(0), count, "Expected policy %s to NOT exist in DB", policyID)
}

// VerifyRouteInDB reads a route directly from the DB and returns it.
func VerifyRouteInDB(t *testing.T, db *gorm.DB, routeID route.ID) *route.Route {
	t.Helper()
	var r route.Route
	err := db.Where("id = ? AND account_id = ?", routeID, TestAccountId).First(&r).Error
	require.NoError(t, err, "Expected route %s to exist in DB", routeID)
	return &r
}

// VerifyRouteNotInDB verifies that a route does not exist in the DB.
func VerifyRouteNotInDB(t *testing.T, db *gorm.DB, routeID route.ID) {
	t.Helper()
	var count int64
	db.Model(&route.Route{}).Where("id = ? AND account_id = ?", routeID, TestAccountId).Count(&count)
	assert.Equal(t, int64(0), count, "Expected route %s to NOT exist in DB", routeID)
}

// VerifyNSGroupInDB reads a nameserver group directly from the DB and returns it.
func VerifyNSGroupInDB(t *testing.T, db *gorm.DB, nsGroupID string) *nbdns.NameServerGroup {
	t.Helper()
	var nsGroup nbdns.NameServerGroup
	err := db.Where("id = ? AND account_id = ?", nsGroupID, TestAccountId).First(&nsGroup).Error
	require.NoError(t, err, "Expected NS group %s to exist in DB", nsGroupID)
	return &nsGroup
}

// VerifyNSGroupNotInDB verifies that a nameserver group does not exist in the DB.
func VerifyNSGroupNotInDB(t *testing.T, db *gorm.DB, nsGroupID string) {
	t.Helper()
	var count int64
	db.Model(&nbdns.NameServerGroup{}).Where("id = ? AND account_id = ?", nsGroupID, TestAccountId).Count(&count)
	assert.Equal(t, int64(0), count, "Expected NS group %s to NOT exist in DB", nsGroupID)
}

// VerifyPeerInDB reads a peer directly from the DB and returns it.
func VerifyPeerInDB(t *testing.T, db *gorm.DB, peerID string) *nbpeer.Peer {
	t.Helper()
	var peer nbpeer.Peer
	err := db.Where("id = ? AND account_id = ?", peerID, TestAccountId).First(&peer).Error
	require.NoError(t, err, "Expected peer %s to exist in DB", peerID)
	return &peer
}

// VerifyPeerNotInDB verifies that a peer does not exist in the DB.
func VerifyPeerNotInDB(t *testing.T, db *gorm.DB, peerID string) {
	t.Helper()
	var count int64
	db.Model(&nbpeer.Peer{}).Where("id = ? AND account_id = ?", peerID, TestAccountId).Count(&count)
	assert.Equal(t, int64(0), count, "Expected peer %s to NOT exist in DB", peerID)
}

// VerifySetupKeyInDB reads a setup key directly from the DB and returns it.
func VerifySetupKeyInDB(t *testing.T, db *gorm.DB, keyID string) *types.SetupKey {
	t.Helper()
	var key types.SetupKey
	err := db.Where("id = ? AND account_id = ?", keyID, TestAccountId).First(&key).Error
	require.NoError(t, err, "Expected setup key %s to exist in DB", keyID)
	return &key
}

// VerifySetupKeyNotInDB verifies that a setup key does not exist in the DB.
func VerifySetupKeyNotInDB(t *testing.T, db *gorm.DB, keyID string) {
	t.Helper()
	var count int64
	db.Model(&types.SetupKey{}).Where("id = ? AND account_id = ?", keyID, TestAccountId).Count(&count)
	assert.Equal(t, int64(0), count, "Expected setup key %s to NOT exist in DB", keyID)
}

// VerifyUserInDB reads a user directly from the DB and returns it.
func VerifyUserInDB(t *testing.T, db *gorm.DB, userID string) *types.User {
	t.Helper()
	var user types.User
	err := db.Where("id = ? AND account_id = ?", userID, TestAccountId).First(&user).Error
	require.NoError(t, err, "Expected user %s to exist in DB", userID)
	return &user
}

// VerifyUserNotInDB verifies that a user does not exist in the DB.
func VerifyUserNotInDB(t *testing.T, db *gorm.DB, userID string) {
	t.Helper()
	var count int64
	db.Model(&types.User{}).Where("id = ? AND account_id = ?", userID, TestAccountId).Count(&count)
	assert.Equal(t, int64(0), count, "Expected user %s to NOT exist in DB", userID)
}

// VerifyPATInDB reads a PAT directly from the DB and returns it.
func VerifyPATInDB(t *testing.T, db *gorm.DB, tokenID string) *types.PersonalAccessToken {
	t.Helper()
	var pat types.PersonalAccessToken
	err := db.Where("id = ?", tokenID).First(&pat).Error
	require.NoError(t, err, "Expected PAT %s to exist in DB", tokenID)
	return &pat
}

// VerifyPATNotInDB verifies that a PAT does not exist in the DB.
func VerifyPATNotInDB(t *testing.T, db *gorm.DB, tokenID string) {
	t.Helper()
	var count int64
	db.Model(&types.PersonalAccessToken{}).Where("id = ?", tokenID).Count(&count)
	assert.Equal(t, int64(0), count, "Expected PAT %s to NOT exist in DB", tokenID)
}

// VerifyAccountSettings reads the account and returns its settings from the DB.
func VerifyAccountSettings(t *testing.T, db *gorm.DB) *types.Account {
	t.Helper()
	var account types.Account
	err := db.Where("id = ?", TestAccountId).First(&account).Error
	require.NoError(t, err, "Expected account %s to exist in DB", TestAccountId)
	return &account
}

// VerifyNetworkInDB reads a network directly from the store and returns it.
func VerifyNetworkInDB(t *testing.T, db *gorm.DB, networkID string) *networkTypes.Network {
	t.Helper()
	var network networkTypes.Network
	err := db.Where("id = ? AND account_id = ?", networkID, TestAccountId).First(&network).Error
	require.NoError(t, err, "Expected network %s to exist in DB", networkID)
	return &network
}

// VerifyNetworkNotInDB verifies that a network does not exist in the DB.
func VerifyNetworkNotInDB(t *testing.T, db *gorm.DB, networkID string) {
	t.Helper()
	var count int64
	db.Model(&networkTypes.Network{}).Where("id = ? AND account_id = ?", networkID, TestAccountId).Count(&count)
	assert.Equal(t, int64(0), count, "Expected network %s to NOT exist in DB", networkID)
}

// VerifyNetworkResourceInDB reads a network resource directly from the DB and returns it.
func VerifyNetworkResourceInDB(t *testing.T, db *gorm.DB, resourceID string) *resourceTypes.NetworkResource {
	t.Helper()
	var resource resourceTypes.NetworkResource
	err := db.Where("id = ? AND account_id = ?", resourceID, TestAccountId).First(&resource).Error
	require.NoError(t, err, "Expected network resource %s to exist in DB", resourceID)
	return &resource
}

// VerifyNetworkResourceNotInDB verifies that a network resource does not exist in the DB.
func VerifyNetworkResourceNotInDB(t *testing.T, db *gorm.DB, resourceID string) {
	t.Helper()
	var count int64
	db.Model(&resourceTypes.NetworkResource{}).Where("id = ? AND account_id = ?", resourceID, TestAccountId).Count(&count)
	assert.Equal(t, int64(0), count, "Expected network resource %s to NOT exist in DB", resourceID)
}

// VerifyNetworkRouterInDB reads a network router directly from the DB and returns it.
func VerifyNetworkRouterInDB(t *testing.T, db *gorm.DB, routerID string) *routerTypes.NetworkRouter {
	t.Helper()
	var router routerTypes.NetworkRouter
	err := db.Where("id = ? AND account_id = ?", routerID, TestAccountId).First(&router).Error
	require.NoError(t, err, "Expected network router %s to exist in DB", routerID)
	return &router
}

// VerifyNetworkRouterNotInDB verifies that a network router does not exist in the DB.
func VerifyNetworkRouterNotInDB(t *testing.T, db *gorm.DB, routerID string) {
	t.Helper()
	var count int64
	db.Model(&routerTypes.NetworkRouter{}).Where("id = ? AND account_id = ?", routerID, TestAccountId).Count(&count)
	assert.Equal(t, int64(0), count, "Expected network router %s to NOT exist in DB", routerID)
}
