package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/util"
)

var (
	listenAddress      string
	letsencryptDataDir string
	letsencryptDomain  string

	rootCmd = &cobra.Command{
		Use:   "relay",
		Short: "Relay service",
		Long:  "Relay service for Netbird agents",
		Run:   execute,
	}
)

func init() {
	_ = util.InitLog("trace", "console")
	rootCmd.PersistentFlags().StringVarP(&listenAddress, "listen-address", "l", ":1235", "listen address")
	rootCmd.PersistentFlags().StringVarP(&letsencryptDataDir, "letsencrypt-data-dir", "d", "", "a directory to store Let's Encrypt data. Required if Let's Encrypt is enabled.")
	rootCmd.PersistentFlags().StringVarP(&letsencryptDomain, "letsencrypt-domain", "a", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
}

func waitForExitSignal() {
	osSigs := make(chan os.Signal, 1)
	signal.Notify(osSigs, syscall.SIGINT, syscall.SIGTERM)
	<-osSigs
}

func execute(cmd *cobra.Command, args []string) {
	srvCfg := server.Config{
		Address: listenAddress,
	}
	if hasLetsEncrypt() {
		tlscfg, err := setupTLS()
		if err != nil {
			log.Errorf("%s", err)
			os.Exit(1)
		}
		srvCfg.TLSConfig = tlscfg
	}

	srv := server.NewServer()
	err := srv.Listen(srvCfg)
	if err != nil {
		log.Errorf("failed to bind server: %s", err)
		os.Exit(1)
	}

	waitForExitSignal()

	err = srv.Close()
	if err != nil {
		log.Errorf("failed to close server: %s", err)
		os.Exit(1)
	}
}

func hasLetsEncrypt() bool {
	return letsencryptDataDir != "" && letsencryptDomain != ""
}

func setupTLS() (*tls.Config, error) {
	certManager, err := encryption.CreateCertManager(letsencryptDataDir, letsencryptDomain)
	if err != nil {
		return nil, fmt.Errorf("failed creating LetsEncrypt cert manager: %v", err)
	}
	return certManager.TLSConfig(), nil
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
