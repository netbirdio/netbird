// Standalone OIDC Identity Provider server
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
)

func main() {
	var (
		issuer    = flag.String("issuer", "http://localhost:33081", "OIDC issuer URL")
		port      = flag.Int("port", 33081, "HTTP port")
		grpcAddr  = flag.String("grpc-addr", "", "gRPC API address (e.g., :5557). Empty disables gRPC API")
		dataDir   = flag.String("data-dir", "./data", "Data directory")
		devMode   = flag.Bool("dev", true, "Development mode")
		addUser   = flag.String("add-user", "", "Add a user (format: email:password)")
		listUsers = flag.Bool("list-users", false, "List all users and exit")
	)
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := &dex.Config{
		Issuer:   *issuer,
		Port:     *port,
		GRPCAddr: *grpcAddr,
		DataDir:  *dataDir,
		DevMode:  *devMode,
	}

	provider, err := dex.NewProvider(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create provider: %v", err)
	}

	// Handle --list-users
	if *listUsers {
		users, err := provider.ListUsers(ctx)
		if err != nil {
			log.Fatalf("Failed to list users: %v", err)
		}
		if len(users) == 0 {
			fmt.Println("No users found")
		} else {
			fmt.Printf("Users (%d):\n", len(users))
			for _, u := range users {
				fmt.Printf("  - %s (%s)\n", u.Email, u.Username)
			}
		}
		return
	}

	// Handle --add-user
	if *addUser != "" {
		parts := strings.SplitN(*addUser, ":", 2)
		if len(parts) != 2 {
			log.Fatalf("Invalid --add-user format. Use: email:password")
		}
		email, password := parts[0], parts[1]
		username := strings.Split(email, "@")[0] // Use part before @ as username

		if err := provider.CreateUser(ctx, email, username, password); err != nil {
			log.Fatalf("Failed to create user: %v", err)
		}
		log.Infof("Created user: %s", email)
	}

	if err := provider.Start(ctx); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	log.Infof("OIDC Provider: %s/dex", config.Issuer)
	log.Infof("Discovery: %s/dex/.well-known/openid-configuration", config.Issuer)
	if config.GRPCAddr != "" {
		log.Infof("gRPC API: %s", config.GRPCAddr)
	}

	// Wait for shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutting down...")
	if err := provider.Stop(ctx); err != nil {
		log.Errorf("Shutdown error: %v", err)
	}
}
