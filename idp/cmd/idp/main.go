// Standalone OIDC Identity Provider server
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
)

func main() {
	var (
		issuer  = flag.String("issuer", "http://localhost:33081", "OIDC issuer URL")
		port    = flag.Int("port", 33081, "HTTP port")
		dataDir = flag.String("data-dir", "./data", "Data directory")
		devMode = flag.Bool("dev", true, "Development mode")
	)
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &dex.Config{
		Issuer:  *issuer,
		Port:    *port,
		DataDir: *dataDir,
		DevMode: *devMode,
	}

	provider, err := dex.NewProvider(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create provider: %v", err)
	}

	if err := provider.Start(ctx); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	log.Infof("OIDC Provider: %s/dex", config.Issuer)
	log.Infof("Discovery: %s/dex/.well-known/openid-configuration", config.Issuer)

	// Wait for shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutting down...")
	if err := provider.Stop(ctx); err != nil {
		log.Errorf("Shutdown error: %v", err)
	}
}
