package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/crypto/acme/autocert"

	"github.com/netbirdio/netbird/signal/metrics"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/util"
	"github.com/netbirdio/netbird/version"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

var (
	signalPort              int
	metricsPort             int
	signalLetsencryptDomain string
	signalSSLDir            string
	defaultSignalSSLDir     string
	signalCertFile          string
	signalCertKey           string

	signalKaep = grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	})

	signalKasp = grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Second,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  5 * time.Second,
		Timeout:               2 * time.Second,
	})

	runCmd = &cobra.Command{
		Use:          "run",
		Short:        "start NetBird Signal Server daemon",
		SilenceUsage: true,
		PreRun: func(cmd *cobra.Command, args []string) {
			err := util.InitLog(logLevel, logFile)
			if err != nil {
				log.Fatalf("failed initializing log %v", err)
			}

			flag.Parse()

			// detect whether user specified a port
			userPort := cmd.Flag("port").Changed

			tlsEnabled := false
			if signalLetsencryptDomain != "" || (signalCertFile != "" && signalCertKey != "") {
				tlsEnabled = true
			}

			if !userPort {
				// different defaults for signalPort
				if tlsEnabled {
					signalPort = 443
				} else {
					signalPort = 80
				}
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			flag.Parse()

			opts, certManager, err := getTLSConfigurations()
			if err != nil {
				return err
			}

			metricsServer, err := metrics.NewServer(metricsPort, "")
			if err != nil {
				return fmt.Errorf("setup metrics: %v", err)
			}

			opts = append(opts, signalKaep, signalKasp, grpc.StatsHandler(otelgrpc.NewServerHandler()))
			grpcServer := grpc.NewServer(opts...)

			go func() {
				log.Infof("running metrics server: %s%s", metricsServer.Addr, metricsServer.Endpoint)
				if err := metricsServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
					log.Fatalf("Failed to start metrics server: %v", err)
				}
			}()

			srv, err := server.NewServer(cmd.Context(), metricsServer.Meter)
			if err != nil {
				return fmt.Errorf("creating signal server: %v", err)
			}
			proto.RegisterSignalExchangeServer(grpcServer, srv)

			grpcRootHandler := grpcHandlerFunc(grpcServer)

			if certManager != nil {
				startServerWithCertManager(certManager, grpcRootHandler)
			}

			var compatListener net.Listener
			var grpcListener net.Listener
			var httpListener net.Listener

			// If certManager is configured and signalPort == 443, then the gRPC server has already been started
			if certManager == nil || signalPort != 443 {
				grpcListener, err = serveGRPC(grpcServer, signalPort)
				if err != nil {
					return err
				}
				log.Infof("running gRPC server: %s", grpcListener.Addr().String())
			}

			if signalPort != 10000 {
				// The Signal gRPC server was running on port 10000 previously. Old agents that are already connected to Signal
				// are using port 10000. For compatibility purposes we keep running a 2nd gRPC server on port 10000.
				compatListener, err = serveGRPC(grpcServer, 10000)
				if err != nil {
					return err
				}
				log.Infof("running gRPC backward compatibility server: %s", compatListener.Addr().String())
			}

			log.Infof("signal server version %s", version.NetbirdVersion())
			log.Infof("started Signal Service")

			SetupCloseHandler()

			<-stopCh
			if grpcListener != nil {
				_ = grpcListener.Close()
				log.Infof("stopped gRPC server")
			}
			if httpListener != nil {
				_ = httpListener.Close()
				log.Infof("stopped HTTP server")
			}
			if compatListener != nil {
				_ = compatListener.Close()
				log.Infof("stopped gRPC backward compatibility server")
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			if err := metricsServer.Shutdown(ctx); err != nil {
				log.Errorf("Failed to stop metrics server: %v", err)
			}
			log.Infof("stopped metrics server")

			log.Infof("stopped Signal Service")

			return nil
		},
	}
)

func getTLSConfigurations() ([]grpc.ServerOption, *autocert.Manager, error) {
	var (
		err         error
		certManager *autocert.Manager
		tlsConfig   *tls.Config
	)

	if signalLetsencryptDomain == "" && signalCertFile == "" && signalCertKey == "" {
		log.Infof("running without TLS")
		return nil, nil, nil
	}

	if signalLetsencryptDomain != "" {
		certManager, err = encryption.CreateCertManager(signalSSLDir, signalLetsencryptDomain)
		if err != nil {
			return nil, certManager, err
		}
		tlsConfig = certManager.TLSConfig()
		log.Infof("setting up TLS with LetsEncrypt.")
	} else {
		if signalCertFile == "" || signalCertKey == "" {
			log.Errorf("both cert-file and cert-key must be provided when not using LetsEncrypt")
			return nil, certManager, errors.New("both cert-file and cert-key must be provided when not using LetsEncrypt")
		}

		tlsConfig, err = loadTLSConfig(signalCertFile, signalCertKey)
		if err != nil {
			log.Errorf("cannot load TLS credentials: %v", err)
			return nil, certManager, err
		}
		log.Infof("setting up TLS with custom certificates.")
	}

	transportCredentials := credentials.NewTLS(tlsConfig)

	return []grpc.ServerOption{grpc.Creds(transportCredentials)}, certManager, err
}

func startServerWithCertManager(certManager *autocert.Manager, grpcRootHandler http.Handler) {
	// a call to certManager.Listener() always creates a new listener so we do it once
	httpListener := certManager.Listener()
	if signalPort == 443 {
		// running gRPC and HTTP cert manager on the same port
		serveHTTP(httpListener, certManager.HTTPHandler(grpcRootHandler))
		log.Infof("running HTTP server (LetsEncrypt challenge handler) and gRPC server on the same port: %s", httpListener.Addr().String())
	} else {
		// Start the HTTP cert manager server separately
		serveHTTP(httpListener, certManager.HTTPHandler(nil))
		log.Infof("running HTTP server (LetsEncrypt challenge handler): %s", httpListener.Addr().String())
	}
}

func grpcHandlerFunc(grpcServer *grpc.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grpcHeader := strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") ||
			strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc+proto")
		if r.ProtoMajor == 2 && grpcHeader {
			grpcServer.ServeHTTP(w, r)
		}
	})
}

func notifyStop(msg string) {
	select {
	case stopCh <- 1:
		log.Error(msg)
	default:
		// stop has been already called, nothing to report
	}
}

func serveHTTP(httpListener net.Listener, handler http.Handler) {
	go func() {
		err := http.Serve(httpListener, handler)
		if err != nil {
			notifyStop(fmt.Sprintf("failed running HTTP server %v", err))
		}
	}()
}

func serveGRPC(grpcServer *grpc.Server, port int) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	go func() {
		err := grpcServer.Serve(listener)
		if err != nil {
			notifyStop(fmt.Sprintf("failed running gRPC server on port %d: %v", port, err))
		}
	}()
	return listener, nil
}

func loadTLSConfig(certFile string, certKey string) (*tls.Config, error) {
	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(certFile, certKey)
	if err != nil {
		return nil, err
	}

	// NewDefaultAppMetrics the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		NextProtos: []string{
			"h2", "http/1.1", // enable HTTP/2
		},
	}

	return config, nil
}

func init() {
	runCmd.PersistentFlags().IntVar(&signalPort, "port", 80, "Server port to listen on (defaults to 443 if TLS is enabled, 80 otherwise")
	runCmd.Flags().IntVar(&metricsPort, "metrics-port", 9090, "metrics endpoint http port. Metrics are accessible under host:metrics-port/metrics")
	runCmd.Flags().StringVar(&signalSSLDir, "ssl-dir", defaultSignalSSLDir, "server ssl directory location. *Required only for Let's Encrypt certificates.")
	runCmd.Flags().StringVar(&signalLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
	runCmd.Flags().StringVar(&signalCertFile, "cert-file", "", "Location of your SSL certificate. Can be used when you have an existing certificate and don't want a new certificate be generated automatically. If letsencrypt-domain is specified this property has no effect")
	runCmd.Flags().StringVar(&signalCertKey, "cert-key", "", "Location of your SSL certificate private key. Can be used when you have an existing certificate and don't want a new certificate be generated automatically. If letsencrypt-domain is specified this property has no effect")
}
