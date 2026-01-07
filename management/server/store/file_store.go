package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	nbutil "github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/util/crypt"
)

// storeFileName Store file name. Stored in the datadir
const storeFileName = "store.json"

// FileStore represents an account storage backed by a file persisted to disk
type FileStore struct {
	Accounts                map[string]*types.Account
	SetupKeyID2AccountID    map[string]string `json:"-"`
	PeerKeyID2AccountID     map[string]string `json:"-"`
	PeerID2AccountID        map[string]string `json:"-"`
	UserID2AccountID        map[string]string `json:"-"`
	PrivateDomain2AccountID map[string]string `json:"-"`
	HashedPAT2TokenID       map[string]string `json:"-"`
	TokenID2UserID          map[string]string `json:"-"`
	InstallationID          string

	// mutex to synchronise Store read/write operations
	mux       sync.Mutex `json:"-"`
	storeFile string     `json:"-"`

	metrics telemetry.AppMetrics `json:"-"`
}

// NewFileStore restores a store from the file located in the datadir
func NewFileStore(ctx context.Context, dataDir string, metrics telemetry.AppMetrics) (*FileStore, error) {
	fs, err := restore(ctx, filepath.Join(dataDir, storeFileName))
	if err != nil {
		return nil, err
	}
	fs.metrics = metrics
	return fs, nil
}

// restore the state of the store from the file.
// Creates a new empty store file if doesn't exist
func restore(ctx context.Context, file string) (*FileStore, error) {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		// create a new FileStore if previously didn't exist (e.g. first run)
		s := &FileStore{
			Accounts:                make(map[string]*types.Account),
			mux:                     sync.Mutex{},
			SetupKeyID2AccountID:    make(map[string]string),
			PeerKeyID2AccountID:     make(map[string]string),
			UserID2AccountID:        make(map[string]string),
			PrivateDomain2AccountID: make(map[string]string),
			PeerID2AccountID:        make(map[string]string),
			HashedPAT2TokenID:       make(map[string]string),
			TokenID2UserID:          make(map[string]string),
			storeFile:               file,
		}

		err = s.persist(ctx, file)
		if err != nil {
			return nil, err
		}

		return s, nil
	}

	read, err := util.ReadJson(file, &FileStore{})
	if err != nil {
		return nil, err
	}

	store := read.(*FileStore)
	store.storeFile = file
	store.SetupKeyID2AccountID = make(map[string]string)
	store.PeerKeyID2AccountID = make(map[string]string)
	store.UserID2AccountID = make(map[string]string)
	store.PrivateDomain2AccountID = make(map[string]string)
	store.PeerID2AccountID = make(map[string]string)
	store.HashedPAT2TokenID = make(map[string]string)
	store.TokenID2UserID = make(map[string]string)

	for accountID, account := range store.Accounts {
		if account.Settings == nil {
			account.Settings = &types.Settings{
				PeerLoginExpirationEnabled: false,
				PeerLoginExpiration:        types.DefaultPeerLoginExpiration,

				PeerInactivityExpirationEnabled: false,
				PeerInactivityExpiration:        types.DefaultPeerInactivityExpiration,

				RoutingPeerDNSResolutionEnabled: true,
			}
		}

		for setupKeyId := range account.SetupKeys {
			store.SetupKeyID2AccountID[strings.ToUpper(setupKeyId)] = accountID
		}

		for _, peer := range account.Peers {
			store.PeerKeyID2AccountID[peer.Key] = accountID
			store.PeerID2AccountID[peer.ID] = accountID
		}
		for _, user := range account.Users {
			store.UserID2AccountID[user.Id] = accountID
			if user.Issued == "" {
				user.Issued = types.UserIssuedAPI
				account.Users[user.Id] = user
			}

			for _, pat := range user.PATs {
				store.TokenID2UserID[pat.ID] = user.Id
				store.HashedPAT2TokenID[pat.HashedToken] = pat.ID
			}
		}

		if account.Domain != "" && account.DomainCategory == types.PrivateCategory &&
			account.IsDomainPrimaryAccount {
			store.PrivateDomain2AccountID[account.Domain] = accountID
		}

		// TODO: delete this block after migration
		policies := make(map[string]int, len(account.Policies))
		for i, policy := range account.Policies {
			policies[policy.ID] = i
			policy.UpgradeAndFix()
		}
		if account.Policies == nil {
			account.Policies = make([]*types.Policy, 0)
		}

		// for data migration. Can be removed once most base will be with labels
		existingLabels := account.GetPeerDNSLabels()
		if len(existingLabels) != len(account.Peers) {
			types.AddPeerLabelsToAccount(ctx, account, existingLabels)
		}

		// TODO: delete this block after migration
		// Set API as issuer for groups which has not this field
		for _, group := range account.Groups {
			if group.Issued == "" {
				group.Issued = types.GroupIssuedAPI
			}
		}

		allGroup, err := account.GetGroupAll()
		if err != nil {
			log.WithContext(ctx).Errorf("unable to find the All group, this should happen only when migratePreAuto from a version that didn't support groups. Error: %v", err)
			// if the All group didn't exist we probably don't have routes to update
			continue
		}

		for _, route := range account.Routes {
			if len(route.Groups) == 0 {
				route.Groups = []string{allGroup.ID}
			}
		}

		// migration to Peer.ID from Peer.Key.
		// Old peers that require migration have an empty Peer.ID in the store.json.
		// Generate new ID with xid for these peers.
		// Set the Peer.ID to the newly generated value.
		// Replace all the mentions of Peer.Key as ID (groups and routes).
		// Swap Peer.Key with Peer.ID in the Account.Peers map.
		migrationPeers := make(map[string]*nbpeer.Peer) // key to Peer
		for key, peer := range account.Peers {
			// set LastLogin for the peers that were onboarded before the peer login expiration feature
			if peer.GetLastLogin().IsZero() {
				peer.LastLogin = nbutil.ToPtr(time.Now().UTC())
			}
			if peer.ID != "" {
				continue
			}
			id := xid.New().String()
			peer.ID = id
			migrationPeers[key] = peer
		}

		if len(migrationPeers) > 0 {
			// swap Peer.Key with Peer.ID in the Account.Peers map.
			for key, peer := range migrationPeers {
				delete(account.Peers, key)
				account.Peers[peer.ID] = peer
				store.PeerID2AccountID[peer.ID] = accountID
			}

			// detect groups that have Peer.Key as a reference and replace it with ID.
			for _, group := range account.Groups {
				for i, peer := range group.Peers {
					if p, ok := migrationPeers[peer]; ok {
						group.Peers[i] = p.ID
					}
				}
			}

			// detect routes that have Peer.Key as a reference and replace it with ID.
			for _, route := range account.Routes {
				if peer, ok := migrationPeers[route.Peer]; ok {
					route.Peer = peer.ID
				}
			}
		}
	}

	// we need this persist to apply changes we made to account.Peers (we set them to Disconnected)
	err = store.persist(ctx, store.storeFile)
	if err != nil {
		return nil, err
	}

	return store, nil
}

// persist account data to a file
// It is recommended to call it with locking FileStore.mux
func (s *FileStore) persist(ctx context.Context, file string) error {
	start := time.Now()
	err := util.WriteJson(context.Background(), file, s)
	if err != nil {
		return err
	}
	took := time.Since(start)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountPersistenceDuration(took)
	}
	log.WithContext(ctx).Debugf("took %d ms to persist the FileStore", took.Milliseconds())
	return nil
}

// GetAllAccounts returns all accounts
func (s *FileStore) GetAllAccounts(_ context.Context) (all []*types.Account) {
	s.mux.Lock()
	defer s.mux.Unlock()
	for _, a := range s.Accounts {
		all = append(all, a.Copy())
	}

	return all
}

// Close the FileStore persisting data to disk
func (s *FileStore) Close(ctx context.Context) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	log.WithContext(ctx).Infof("closing FileStore")

	return s.persist(ctx, s.storeFile)
}

// GetStoreEngine returns FileStoreEngine
func (s *FileStore) GetStoreEngine() types.Engine {
	return types.FileStoreEngine
}

// SetFieldEncrypt is a no-op for FileStore as it doesn't support field encryption.
func (s *FileStore) SetFieldEncrypt(_ *crypt.FieldEncrypt) {
	// no-op: FileStore stores data in plaintext JSON; encryption is not supported
}
