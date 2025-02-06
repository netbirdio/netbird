// Package embed provides a way to embed the NetBird client directly
// into Go programs without requiring a separate NetBird client installation.
package embed

// Basic Usage:
//
//	client, err := embed.New(embed.Options{
//	    DeviceName:    "my-service",
//	    SetupKey:      os.Getenv("NB_SETUP_KEY"),
//	    ManagementURL: os.Getenv("NB_MANAGEMENT_URL"),
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	if err := client.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// Complete HTTP Server Example:
//
//	package main
//
//	import (
//	    "context"
//	    "fmt"
//	    "log"
//	    "net/http"
//	    "os"
//	    "os/signal"
//	    "syscall"
//	    "time"
//
//	    netbird "github.com/netbirdio/netbird/client/embed"
//	)
//
//	func main() {
//	    // Create client with setup key and device name
//	    client, err := netbird.New(netbird.Options{
//	        DeviceName:    "http-server",
//	        SetupKey:      os.Getenv("NB_SETUP_KEY"),
//	        ManagementURL: os.Getenv("NB_MANAGEMENT_URL"),
//	        LogOutput:     io.Discard,
//	    })
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Start with timeout
//	    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	    defer cancel()
//	    if err := client.Start(ctx); err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Create HTTP server
//	    mux := http.NewServeMux()
//	    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
//	        fmt.Printf("Request from %s: %s %s\n", r.RemoteAddr, r.Method, r.URL.Path)
//	        fmt.Fprintf(w, "Hello from netbird!")
//	    })
//
//	    // Listen on netbird network
//	    l, err := client.ListenTCP(":8080")
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    server := &http.Server{Handler: mux}
//	    go func() {
//	        if err := server.Serve(l); !errors.Is(err, http.ErrServerClosed) {
//	            log.Printf("HTTP server error: %v", err)
//	        }
//	    }()
//
//	    log.Printf("HTTP server listening on netbird network port 8080")
//
//	    // Handle shutdown
//	    stop := make(chan os.Signal, 1)
//	    signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
//	    <-stop
//
//	    shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	    defer cancel()
//
//	    if err := server.Shutdown(shutdownCtx); err != nil {
//	        log.Printf("HTTP shutdown error: %v", err)
//	    }
//	    if err := client.Stop(shutdownCtx); err != nil {
//	        log.Printf("Netbird shutdown error: %v", err)
//	    }
//	}
//
// Complete HTTP Client Example:
//
//	package main
//
//	import (
//	    "context"
//	    "fmt"
//	    "io"
//	    "log"
//	    "os"
//	    "time"
//
//	    netbird "github.com/netbirdio/netbird/client/embed"
//	)
//
//	func main() {
//	    // Create client with setup key and device name
//	    client, err := netbird.New(netbird.Options{
//	        DeviceName:    "http-client",
//	        SetupKey:      os.Getenv("NB_SETUP_KEY"),
//	        ManagementURL: os.Getenv("NB_MANAGEMENT_URL"),
//	        LogOutput:     io.Discard,
//	    })
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Start with timeout
//	    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	    defer cancel()
//
//	    if err := client.Start(ctx); err != nil {
//	        log.Fatal(err)
//	    }
//
//	    // Create HTTP client that uses netbird network
//	    httpClient := client.NewHTTPClient()
//	    httpClient.Timeout = 10 * time.Second
//
//	    // Make request to server in netbird network
//	    target := os.Getenv("NB_TARGET")
//	    resp, err := httpClient.Get(target)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    defer resp.Body.Close()
//
//	    // Read and print response
//	    body, err := io.ReadAll(resp.Body)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    fmt.Printf("Response from server: %s\n", string(body))
//
//	    // Clean shutdown
//	    shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	    defer cancel()
//
//	    if err := client.Stop(shutdownCtx); err != nil {
//	        log.Printf("Netbird shutdown error: %v", err)
//	    }
//	}
//
// The package provides several methods for network operations:
//   - Dial: Creates outbound connections
//   - ListenTCP: Creates TCP listeners
//   - ListenUDP: Creates UDP listeners
//
// By default, the embed package uses userspace networking mode, which doesn't
// require root/admin privileges. For production deployments, consider setting
// appropriate config and state paths for persistence.
