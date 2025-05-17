package sqlite

import (
	"context"
	"fmt"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/server/activity"
)

const (
	// eventSinkDB is the default name of the events database
	eventSinkDB = "events.db"

	fallbackName  = "unknown"
	fallbackEmail = "unknown@unknown.com"

	gcmEncAlgo = "GCM"
)

type eventWithNames struct {
	activity.Event
	InitiatorName  string
	InitiatorEmail string
	TargetName     string
	TargetEmail    string
}

// Store is the implementation of the activity.Store interface backed by SQLite
type Store struct {
	db           *gorm.DB
	fieldEncrypt *FieldEncrypt
}

// NewSQLiteStore creates a new Store with an event table if not exists.
func NewSQLiteStore(ctx context.Context, dataDir string, encryptionKey string) (*Store, error) {
	crypt, err := NewFieldEncrypt(encryptionKey)
	if err != nil {

		return nil, err
	}

	dbFile := filepath.Join(dataDir, eventSinkDB)
	db, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	sql, err := db.DB()
	if err != nil {
		return nil, err
	}
	sql.SetMaxOpenConns(1)

	if err = migrate(ctx, crypt, db); err != nil {
		return nil, fmt.Errorf("events database migration: %w", err)
	}

	err = db.AutoMigrate(&activity.Event{}, &activity.DeletedUser{})
	if err != nil {
		return nil, fmt.Errorf("events auto migrate: %w", err)
	}

	return &Store{
		db:           db,
		fieldEncrypt: crypt,
	}, nil
}

func (store *Store) processResult(ctx context.Context, events []*eventWithNames) ([]*activity.Event, error) {
	activityEvents := make([]*activity.Event, 0)
	var cryptErr error

	for _, event := range events {
		e := event.Event
		if e.Meta == nil {
			e.Meta = make(map[string]any)
		}

		if event.TargetName != "" {
			name, err := store.fieldEncrypt.Decrypt(event.TargetName)
			if err != nil {
				cryptErr = fmt.Errorf("failed to decrypt username for target id: %s", event.TargetName)
				e.Meta["username"] = fallbackName
			} else {
				e.Meta["username"] = name
			}
		}

		if event.TargetEmail != "" {
			email, err := store.fieldEncrypt.Decrypt(event.TargetEmail)
			if err != nil {
				cryptErr = fmt.Errorf("failed to decrypt email address for target id: %s", event.TargetEmail)
				e.Meta["email"] = fallbackEmail
			} else {
				e.Meta["email"] = email
			}
		}

		if event.InitiatorName != "" {
			name, err := store.fieldEncrypt.Decrypt(event.InitiatorName)
			if err != nil {
				cryptErr = fmt.Errorf("failed to decrypt username of initiator: %s", event.InitiatorName)
				e.InitiatorName = fallbackName
			} else {
				e.InitiatorName = name
			}
		}

		if event.InitiatorEmail != "" {
			email, err := store.fieldEncrypt.Decrypt(event.InitiatorEmail)
			if err != nil {
				cryptErr = fmt.Errorf("failed to decrypt email address of initiator: %s", event.InitiatorEmail)
				e.InitiatorEmail = fallbackEmail
			} else {
				e.InitiatorEmail = email
			}
		}

		activityEvents = append(activityEvents, &e)
	}

	if cryptErr != nil {
		log.WithContext(ctx).Warnf("%s", cryptErr)
	}

	return activityEvents, nil
}

// Get returns "limit" number of events from index ordered descending or ascending by a timestamp
func (store *Store) Get(ctx context.Context, accountID string, offset, limit int, descending bool) ([]*activity.Event, error) {
	baseQuery := store.db.Model(&activity.Event{}).
		Select(`
      events.*,
      u.name  AS initiator_name,
      u.email AS initiator_email,
      t.name  AS target_name,
      t.email AS target_email
    `).
		Joins(`LEFT JOIN deleted_users u ON u.id = events.initiator_id`).
		Joins(`LEFT JOIN deleted_users t ON t.id = events.target_id`)

	orderDir := "DESC"
	if !descending {
		orderDir = "ASC"
	}

	var events []*eventWithNames
	err := baseQuery.Order("events.timestamp "+orderDir).Offset(offset).Limit(limit).
		Find(&events, "account_id = ?", accountID).Error
	if err != nil {
		return nil, err
	}

	return store.processResult(ctx, events)
}

// Save an event in the SQLite events table end encrypt the "email" element in meta map
func (store *Store) Save(_ context.Context, event *activity.Event) (*activity.Event, error) {
	eventCopy := event.Copy()
	meta, err := store.saveDeletedUserEmailAndNameInEncrypted(eventCopy)
	if err != nil {
		return nil, err
	}
	eventCopy.Meta = meta

	if err = store.db.Create(eventCopy).Error; err != nil {
		return nil, err
	}

	return eventCopy, nil
}

// saveDeletedUserEmailAndNameInEncrypted if the meta contains email and name then store it in encrypted way and delete
// this item from meta map
func (store *Store) saveDeletedUserEmailAndNameInEncrypted(event *activity.Event) (map[string]any, error) {
	email, ok := event.Meta["email"]
	if !ok {
		return event.Meta, nil
	}

	name, ok := event.Meta["name"]
	if !ok {
		return event.Meta, nil
	}

	deletedUser := activity.DeletedUser{
		ID:      event.TargetID,
		EncAlgo: gcmEncAlgo,
	}

	encryptedEmail, err := store.fieldEncrypt.Encrypt(fmt.Sprintf("%s", email))
	if err != nil {
		return nil, err
	}
	deletedUser.Email = encryptedEmail

	encryptedName, err := store.fieldEncrypt.Encrypt(fmt.Sprintf("%s", name))
	if err != nil {
		return nil, err
	}
	deletedUser.Name = encryptedName

	err = store.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"email", "name"}),
	}).Create(deletedUser).Error
	if err != nil {
		return nil, err
	}

	if len(event.Meta) == 2 {
		return nil, nil // nolint
	}
	delete(event.Meta, "email")
	delete(event.Meta, "name")
	return event.Meta, nil
}

// Close the Store
func (store *Store) Close(_ context.Context) error {
	if store.db != nil {
		sql, err := store.db.DB()
		if err != nil {
			return err
		}
		return sql.Close()
	}
	return nil
}
