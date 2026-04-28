package manager

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/credentials"
	"github.com/netbirdio/netbird/management/internals/modules/credentials/secretpayload"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/util/crypt"
)

const testKeyB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// cfSecret is a shorthand for the typical single-token Cloudflare
// credential shape used throughout these tests.
func cfSecret(token string) map[string]string {
	return map[string]string{"auth_token": token}
}

func newCryptForTest(t *testing.T) *crypt.FieldEncrypt {
	t.Helper()
	enc, err := crypt.NewFieldEncrypt(testKeyB64)
	require.NoError(t, err)
	return enc
}

// fakeStore is a minimal in-memory store satisfying CredentialStore.
type fakeStore struct {
	mu      sync.Mutex
	records map[string]*credentials.Credential
}

func newFakeStore() *fakeStore {
	return &fakeStore{records: map[string]*credentials.Credential{}}
}

func (f *fakeStore) CreateCredential(_ context.Context, c *credentials.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[c.AccountID+"|"+c.ID] = c
	return nil
}

func (f *fakeStore) GetCredentialByRef(_ context.Context, accountID, ref string) (*credentials.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.records[accountID+"|"+ref]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *c
	return &cp, nil
}

func (f *fakeStore) ListCredentialsByAccount(_ context.Context, accountID, providerTypeFilter string) ([]*credentials.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*credentials.Credential
	for k, c := range f.records {
		if !startsWith(k, accountID+"|") {
			continue
		}
		if providerTypeFilter != "" && c.ProviderType != providerTypeFilter {
			continue
		}
		cp := *c
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeStore) UpdateCredential(_ context.Context, c *credentials.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := c.AccountID + "|" + c.ID
	if _, ok := f.records[key]; !ok {
		return errors.New("not found")
	}
	cp := *c
	f.records[key] = &cp
	return nil
}

func (f *fakeStore) DeleteCredential(_ context.Context, accountID, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.records, accountID+"|"+ref)
	return nil
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// fakeEvents counts StoreEvent calls per activity ID.
type fakeEvents struct {
	mu     sync.Mutex
	counts map[string]int
}

func newFakeEvents() *fakeEvents {
	return &fakeEvents{counts: map[string]int{}}
}

func (f *fakeEvents) StoreEvent(_ context.Context, _, _, _ string, activityID activity.ActivityDescriber, _ map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[activityID.StringCode()]++
}

func (f *fakeEvents) Count(code string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[code]
}

func TestCreateEncryptsAndScrubsResponse(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	const plaintext = "cf_supersecret_token"
	rec, err := mgr.Create(context.Background(), "acc1", "user1", "cloudflare", "main", cfSecret(plaintext))
	require.NoError(t, err)
	require.NotEmpty(t, rec.ID)

	// Response is scrubbed.
	assert.Empty(t, rec.EncryptedSecret, "Create response must not carry the ciphertext")

	// Stored record holds ciphertext, not plaintext.
	stored := store.records["acc1|"+rec.ID]
	require.NotNil(t, stored)
	assert.NotEmpty(t, stored.EncryptedSecret)
	assert.NotContains(t, stored.EncryptedSecret, plaintext, "stored EncryptedSecret must not contain the plaintext")

	// Audit recorded.
	assert.Equal(t, 1, events.Count(activity.CredentialCreated.StringCode()))
}

func TestGetMetadataDoesNotDecryptOrAudit(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	rec, err := mgr.Create(context.Background(), "acc1", "user1", "cloudflare", "main", cfSecret("secret"))
	require.NoError(t, err)

	got, err := mgr.GetMetadata(context.Background(), "acc1", "user1", rec.ID)
	require.NoError(t, err)
	assert.Equal(t, rec.ID, got.ID)
	assert.Empty(t, got.EncryptedSecret, "GetMetadata must scrub the ciphertext")
	assert.Equal(t, 0, events.Count(activity.CredentialRead.StringCode()),
		"GetMetadata must not audit-log a read")
}

func TestGetByRefWithSecretDecryptsAndAudits(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	const plaintext = "cf_supersecret_token"
	rec, err := mgr.Create(context.Background(), "acc1", "user1", "cloudflare", "main", cfSecret(plaintext))
	require.NoError(t, err)

	gotRec, gotPlain, err := mgr.GetByRefWithSecret(context.Background(), "acc1", "user1", rec.ID)
	require.NoError(t, err)
	decoded, err := secretpayload.Decode(gotPlain)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decoded["auth_token"], "decoded payload must contain the original plaintext under its provider key")
	assert.Empty(t, gotRec.EncryptedSecret, "the returned record must still have its EncryptedSecret scrubbed")
	assert.Equal(t, 1, events.Count(activity.CredentialRead.StringCode()))
}

func TestListScrubsSecrets(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	for i, name := range []string{"a", "b", "c"} {
		_, err := mgr.Create(context.Background(), "acc1", "user1", "cloudflare", name, cfSecret("secret"))
		require.NoError(t, err, "create %d failed", i)
	}

	recs, err := mgr.List(context.Background(), "acc1", "user1", "")
	require.NoError(t, err)
	assert.Len(t, recs, 3)
	for _, r := range recs {
		assert.Empty(t, r.EncryptedSecret, "List must scrub every record")
	}
}

func TestListFilterByProviderType(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	_, err = mgr.Create(context.Background(), "acc1", "u", "cloudflare", "cf1", cfSecret("s"))
	require.NoError(t, err)
	_, err = mgr.Create(context.Background(), "acc1", "u", "cloudflare", "cf2", cfSecret("s"))
	require.NoError(t, err)
	_, err = mgr.Create(context.Background(), "acc1", "u", "route53", "r53", map[string]string{"access_key_id": "AKIA", "secret_access_key": "shh"})
	require.NoError(t, err)

	cf, err := mgr.List(context.Background(), "acc1", "u", "cloudflare")
	require.NoError(t, err)
	assert.Len(t, cf, 2)

	r53, err := mgr.List(context.Background(), "acc1", "u", "route53")
	require.NoError(t, err)
	assert.Len(t, r53, 1)
}

func TestDeleteRemovesAndAudits(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	rec, err := mgr.Create(context.Background(), "acc1", "user1", "cloudflare", "main", cfSecret("secret"))
	require.NoError(t, err)

	require.NoError(t, mgr.Delete(context.Background(), "acc1", "user1", rec.ID))

	_, err = mgr.GetMetadata(context.Background(), "acc1", "user1", rec.ID)
	require.Error(t, err)

	assert.Equal(t, 1, events.Count(activity.CredentialDeleted.StringCode()))
}

func TestCrossAccountAccessFails(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	rec, err := mgr.Create(context.Background(), "acc1", "user1", "cloudflare", "main", cfSecret("secret"))
	require.NoError(t, err)

	// account 2 attempts to read account 1's ref.
	_, err = mgr.GetMetadata(context.Background(), "acc2", "user2", rec.ID)
	require.Error(t, err)

	_, _, err = mgr.GetByRefWithSecret(context.Background(), "acc2", "user2", rec.ID)
	require.Error(t, err)
}

func TestUpdateRotatesSecret(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	const oldSecret = "cf_old"
	const newSecret = "cf_new"

	rec, err := mgr.Create(context.Background(), "acc1", "user1", "cloudflare", "main", cfSecret(oldSecret))
	require.NoError(t, err)

	updated, err := mgr.Update(context.Background(), "acc1", "user1", rec.ID, "cloudflare", "main", cfSecret(newSecret))
	require.NoError(t, err)
	assert.Equal(t, rec.ID, updated.ID, "ref must be stable on update")
	assert.Empty(t, updated.EncryptedSecret, "Update response must scrub the ciphertext")

	// On disk, the ciphertext changed.
	stored := store.records["acc1|"+rec.ID]
	require.NotNil(t, stored)
	assert.NotContains(t, stored.EncryptedSecret, oldSecret)
	assert.NotContains(t, stored.EncryptedSecret, newSecret)

	// Decrypted payload is JSON-encoded; decode and verify the underlying
	// auth_token field reflects the new secret.
	_, plain, err := mgr.GetByRefWithSecret(context.Background(), "acc1", "user1", rec.ID)
	require.NoError(t, err)
	decoded, err := secretpayload.Decode(plain)
	require.NoError(t, err)
	assert.Equal(t, newSecret, decoded["auth_token"])

	assert.Equal(t, 1, events.Count(activity.CredentialUpdated.StringCode()))
}

func TestUpdateRequiresExistingRecord(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	_, err = mgr.Update(context.Background(), "acc1", "user1", "no-such-ref", "cloudflare", "main", cfSecret("secret"))
	require.Error(t, err)
	assert.Equal(t, 0, events.Count(activity.CredentialUpdated.StringCode()))
}

func TestUpdateCrossAccountFails(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	rec, err := mgr.Create(context.Background(), "acc1", "user1", "cloudflare", "main", cfSecret("secret"))
	require.NoError(t, err)

	_, err = mgr.Update(context.Background(), "acc2", "user2", rec.ID, "cloudflare", "main", cfSecret("newsecret"))
	require.Error(t, err)
}

func TestCreateValidation(t *testing.T) {
	store := newFakeStore()
	events := newFakeEvents()
	enc := newCryptForTest(t)
	mgr, err := New(store, enc, events)
	require.NoError(t, err)

	cases := []struct {
		name, accountID, providerType, label string
		secret                               map[string]string
	}{
		{"empty account", "", "cloudflare", "n", cfSecret("s")},
		{"unknown provider", "acc", "magic-01", "n", cfSecret("s")},
		{"empty name", "acc", "cloudflare", "", cfSecret("s")},
		{"empty secret", "acc", "cloudflare", "n", nil},
		{"empty secret map", "acc", "cloudflare", "n", map[string]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mgr.Create(context.Background(), tc.accountID, "u", tc.providerType, tc.label, tc.secret)
			require.Error(t, err)
		})
	}
}
