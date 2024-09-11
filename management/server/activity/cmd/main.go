package main

import (
	"context"

	_ "github.com/mattn/go-sqlite3"
	"github.com/netbirdio/netbird/management/server/activity/sqlite"
	log "github.com/sirupsen/logrus"
)

func main() {
	encryptionKey := "<enc_key>"
	eventsDBBase := "management/server/activity/cmd/events.db"

	store, err := sqlite.NewSQLiteStore(context.Background(), eventsDBBase, encryptionKey)
	if err != nil {
		log.Fatalf("failed to create sqlite store: %v", err)
	}

	if err = store.GetLegacyEvents(); err != nil {
		log.Fatalf("failed to get legacy events: %v", err)
	}
}
