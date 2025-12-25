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
		configFile = flag.String("config", "", "Path to YAML config file (dex-compatible format)")
		addUser    = flag.String("add-user", "", "Add a user (format: email:password)")
		listUsers  = flag.Bool("list-users", false, "List all users and exit")
	)
	flag.Parse()

	if *configFile == "" {
		log.Fatal("--config flag is required. Please provide a YAML configuration file.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load YAML config
	yamlConfig, err := dex.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	provider, err := dex.NewProviderFromYAML(ctx, yamlConfig)
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

		userID, err := provider.CreateUser(ctx, email, username, password)
		if err != nil {
			log.Fatalf("Failed to create user: %v", err)
		}
		log.Infof("Created user: %s (ID: %s)", email, userID)
	}

	if err := provider.Start(ctx); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	log.Infof("OIDC Provider: %s", yamlConfig.Issuer)
	log.Infof("Discovery: %s/.well-known/openid-configuration", yamlConfig.Issuer)
	if yamlConfig.GRPC.Addr != "" {
		log.Infof("gRPC API: %s", yamlConfig.GRPC.Addr)
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
