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
	listenAddress string
	// in HA every peer connect to a common domain, the instance domain has been distributed during the p2p connection
	// it is a domain:port or ip:port
	exposedAddress     string
	letsencryptDataDir string
	letsencryptDomains []string
	tlsCertFile        string
	tlsKeyFile         string
	authSecret         string

	rootCmd = &cobra.Command{
		Use:   "relay",
		Short: "Relay service",
		Long:  "Relay service for Netbird agents",
		Run:   execute,
	}
)

func init() {
	_ = util.InitLog("trace", "console")
	rootCmd.PersistentFlags().StringVarP(&listenAddress, "listen-address", "l", ":443", "listen address")
	rootCmd.PersistentFlags().StringVarP(&exposedAddress, "exposed-address", "e", "", "instance domain address (or ip) and port, it will be distributes between peers")
	rootCmd.PersistentFlags().StringVarP(&letsencryptDataDir, "letsencrypt-data-dir", "d", "", "a directory to store Let's Encrypt data. Required if Let's Encrypt is enabled.")
	rootCmd.PersistentFlags().StringArrayVarP(&letsencryptDomains, "letsencrypt-domains", "a", nil, "list of domains to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
	rootCmd.PersistentFlags().StringVarP(&tlsCertFile, "tls-cert-file", "c", "", "")
	rootCmd.PersistentFlags().StringVarP(&tlsKeyFile, "tls-key-file", "k", "", "")
	rootCmd.PersistentFlags().StringVarP(&authSecret, "auth-secret", "s", "", "log level")
}

func waitForExitSignal() {
	osSigs := make(chan os.Signal, 1)
	signal.Notify(osSigs, syscall.SIGINT, syscall.SIGTERM)
	<-osSigs
}

func execute(cmd *cobra.Command, args []string) {
	if exposedAddress == "" {
		log.Errorf("exposed address is required")
		os.Exit(1)
	}

	if authSecret == "" {
		log.Errorf("auth secret is required")
		os.Exit(1)
	}

	srvListenerCfg := server.ListenerConfig{
		Address: listenAddress,
	}
	if hasLetsEncrypt() {
		tlsCfg, err := setupTLSCertManager()
		if err != nil {
			log.Errorf("%s", err)
			os.Exit(1)
		}
		srvListenerCfg.TLSConfig = tlsCfg
	} else if hasCertConfig() {
		tlsCfg, err := encryption.LoadTLSConfig(tlsCertFile, tlsKeyFile)
		if err != nil {
			log.Errorf("%s", err)
			os.Exit(1)
		}
		srvListenerCfg.TLSConfig = tlsCfg
	}

	tlsSupport := srvListenerCfg.TLSConfig != nil
	srv := server.NewServer(exposedAddress, tlsSupport, authSecret)
	log.Infof("server will be available on: %s", srv.InstanceURL())
	err := srv.Listen(srvListenerCfg)
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

func hasCertConfig() bool {
	return tlsCertFile != "" && tlsKeyFile != ""

}

func hasLetsEncrypt() bool {
	return letsencryptDataDir != "" && letsencryptDomains != nil && len(letsencryptDomains) > 0
}

func setupTLSCertManager() (*tls.Config, error) {
	certManager, err := encryption.CreateCertManager(letsencryptDataDir, letsencryptDomains...)
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
