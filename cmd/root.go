package cmd

import (
	"crypto/tls"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc/credentials"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
)

const (
	// ExitSetupFailed defines exit code
	ExitSetupFailed = 1
)

var (
	configPath        string
	defaultConfigPath string
	logLevel          string

	rootCmd = &cobra.Command{
		Use:   "wiretrustee",
		Short: "",
		Long:  "",
	}

	// Execution control channel for stopCh signal
	stopCh chan int
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}
func init() {

	stopCh = make(chan int)

	defaultConfigPath = "/etc/wiretrustee/config.json"
	if runtime.GOOS == "windows" {
		defaultConfigPath = os.Getenv("PROGRAMDATA") + "\\Wiretrustee\\" + "config.json"
	}
	rootCmd.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath, "Wiretrustee config file location to write new config to")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "")
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(addPeerCmd)
	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(signalCmd)
	rootCmd.AddCommand(mgmtCmd)
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.AddCommand(runCmd, startCmd, stopCmd, restartCmd) // service control commands are subcommands of service
	serviceCmd.AddCommand(installCmd, uninstallCmd)              // service installer commands are subcommands of service
}

// SetupCloseHandler handles SIGTERM signal and exits with success
func SetupCloseHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			fmt.Println("\r- Ctrl+C pressed in Terminal")
			stopCh <- 0
		}
	}()
}

// InitLog parses and sets log-level input
func InitLog(logLevel string) {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Errorf("Failed parsing log-level %s: %s", logLevel, err)
		os.Exit(ExitSetupFailed)
	}
	log.SetLevel(level)
}

func enableLetsEncrypt(datadir string, letsencryptDomain string) credentials.TransportCredentials {
	certDir := filepath.Join(datadir, "letsencrypt")

	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		err = os.MkdirAll(certDir, os.ModeDir)
		if err != nil {
			log.Fatalf("failed creating Let's encrypt certdir: %s: %v", certDir, err)
		}
	}

	log.Infof("running with Let's encrypt with domain %s. Cert will be stored in %s", letsencryptDomain, certDir)

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(certDir),
		HostPolicy: autocert.HostWhitelist(letsencryptDomain),
	}

	// listener to handle Let's encrypt certificate challenge
	go func() {
		if err := http.Serve(certManager.Listener(), certManager.HTTPHandler(nil)); err != nil {
			log.Fatalf("failed to serve letsencrypt handler: %v", err)
		}
	}()

	return credentials.NewTLS(&tls.Config{GetCertificate: certManager.GetCertificate})
}
