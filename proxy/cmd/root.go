package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/proxy/pkg/proxy"
	"github.com/netbirdio/netbird/proxy/pkg/version"
)

var (
	configFile string
	rootCmd    = &cobra.Command{
		Use:           "proxy",
		Short:         "Netbird Reverse Proxy Server",
		Long:          "A lightweight, configurable reverse proxy server.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          run,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "path to JSON configuration file (optional, can use env vars instead)")

	rootCmd.Version = version.Short()
	rootCmd.SetVersionTemplate("{{.Version}}\n")
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	config, err := proxy.LoadFromFileOrEnv(configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
		return err
	}

	setupLogging(config.LogLevel)

	log.Infof("Starting Netbird Proxy - %s", version.Short())
	log.Debugf("Full version info: %s", version.String())
	log.Info("Configuration loaded successfully")
	log.Infof("Listen Address: %s", config.ReverseProxy.ListenAddress)
	log.Infof("Log Level: %s", config.LogLevel)

	server, err := proxy.NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
		return err
	}

	serverErrors := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			serverErrors <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Fatalf("Server error: %v", err)
		return err
	case sig := <-quit:
		log.Infof("Received signal: %v", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		log.Fatalf("Failed to stop server gracefully: %v", err)
		return err
	}

	log.Info("Server exited successfully")
	return nil
}

func setupLogging(level string) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	switch level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}
