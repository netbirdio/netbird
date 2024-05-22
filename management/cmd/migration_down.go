package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/util"
)

var shortDown = "Rollback SQLite store to JSON file store. Please make a backup of the SQLite file before running this command."

var downCmd = &cobra.Command{
	Use:     "downgrade [--datadir directory] [--log-file console]",
	Aliases: []string{"down"},
	Short:   shortDown,
	Long: shortDown +
		"\n\n" +
		"This command reads the content of {datadir}/store.db and migrates it to {datadir}/store.json that can be used by File store driver.",
	RunE: func(cmd *cobra.Command, args []string) error {
		flag.Parse()
		err := util.InitLog(logLevel, logFile)
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		sqliteStorePath := path.Join(mgmtDataDir, "store.db")
		if _, err := os.Stat(sqliteStorePath); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s doesn't exist, couldn't continue the operation", sqliteStorePath)
		}

		fileStorePath := path.Join(mgmtDataDir, "store.json")
		if _, err := os.Stat(fileStorePath); err == nil {
			return fmt.Errorf("%s already exists, couldn't continue the operation", fileStorePath)
		}

		sqlStore, err := server.NewSqliteStore(mgmtDataDir, nil)
		if err != nil {
			return fmt.Errorf("failed creating file store: %s: %v", mgmtDataDir, err)
		}

		sqliteStoreAccounts := len(sqlStore.GetAllAccounts())
		log.Infof("%d account will be migrated from sqlite store %s to file store %s",
			sqliteStoreAccounts, sqliteStorePath, fileStorePath)

		store, err := server.NewFilestoreFromSqliteStore(sqlStore, mgmtDataDir, nil)
		if err != nil {
			return fmt.Errorf("failed creating file store: %s: %v", mgmtDataDir, err)
		}

		fsStoreAccounts := len(store.GetAllAccounts())
		if fsStoreAccounts != sqliteStoreAccounts {
			return fmt.Errorf("failed to migrate accounts from sqlite to file[]. Expected accounts: %d, got: %d",
				sqliteStoreAccounts, fsStoreAccounts)
		}

		log.Info("Migration finished successfully")

		return nil
	},
}
