package cmd

import (
	"context"
	"flag"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/formatter"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/util"
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

		//nolint
		ctx := context.WithValue(cmd.Context(), formatter.ExecutionContextKey, formatter.SystemSource)

		if err := store.MigrateFileStoreToSqlite(ctx, mgmtDataDir); err != nil {
			return err
		}
		log.WithContext(ctx).Info("Migration finished successfully")

		return nil
	},
}
