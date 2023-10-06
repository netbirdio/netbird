package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var shortUp = "Migrate JSON file store to SQLite store. Please make a backup of the JSON file before running this command."

var upCmd = &cobra.Command{
	Use:     "upgrade [--datadir directory] [--log-file console]",
	Aliases: []string{"up"},
	Short:   shortUp,
	Long: shortUp +
		"\n\n" +
		"This command reads the content of {datadir}/store.json and migrates it to {datadir}/store.db that can be used by SQLite store driver.",
	RunE: func(cmd *cobra.Command, args []string) error {
		flag.Parse()
		err := util.InitLog(logLevel, logFile)
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		fileStorePath := path.Join(mgmtDataDir, "store.json")
		if _, err := os.Stat(fileStorePath); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s doesn't exist, couldn't continue the operation", fileStorePath)
		}

		sqlStorePath := path.Join(mgmtDataDir, "store.db")
		if _, err := os.Stat(sqlStorePath); err == nil {
			return fmt.Errorf("%s already exists, couldn't continue the operation", sqlStorePath)
		}

		fstore, err := server.NewFileStore(mgmtDataDir, nil)
		if err != nil {
			return fmt.Errorf("failed creating file store: %s: %v", mgmtDataDir, err)
		}

		fsStoreAccounts := len(fstore.GetAllAccounts())
		log.Infof("%d account will be migrated from file store %s to sqlite store %s",
			fsStoreAccounts, fileStorePath, sqlStorePath)

		store, err := server.NewSqliteStoreFromFileStore(fstore, mgmtDataDir, nil)
		if err != nil {
			return fmt.Errorf("failed creating file store: %s: %v", mgmtDataDir, err)
		}

		sqliteStoreAccounts := len(store.GetAllAccounts())
		if fsStoreAccounts != sqliteStoreAccounts {
			return fmt.Errorf("failed to migrate accounts from file to sqlite. Expected accounts: %d, got: %d",
				fsStoreAccounts, sqliteStoreAccounts)
		}

		log.Info("Migration finished successfully")

		return nil
	},
}
