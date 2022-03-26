package cmd

import (
	"flag"
	"fmt"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"net"
	"net/http"
	"os"
	"time"
)

var (
	signalPort              int
	signalLetsencryptDomain string
	signalSSLDir            string

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
		Use:   "run",
		Short: "start Wiretrustee Signal Server daemon",
		Run: func(cmd *cobra.Command, args []string) {
			flag.Parse()
			err := util.InitLog(logLevel, logFile)
			if err != nil {
				log.Fatalf("failed initializing log %v", err)
			}

			var opts []grpc.ServerOption
			if signalLetsencryptDomain != "" {
				if _, err := os.Stat(signalSSLDir); os.IsNotExist(err) {
					err = os.MkdirAll(signalSSLDir, os.ModeDir)
					if err != nil {
						log.Fatalf("failed creating datadir: %s: %v", signalSSLDir, err)
					}
				}
				certManager := encryption.CreateCertManager(signalSSLDir, signalLetsencryptDomain)
				transportCredentials := credentials.NewTLS(certManager.TLSConfig())
				opts = append(opts, grpc.Creds(transportCredentials))

				listener := certManager.Listener()
				log.Infof("http server listening on %s", listener.Addr())
				go func() {
					if err := http.Serve(listener, certManager.HTTPHandler(nil)); err != nil {
						log.Errorf("failed to serve https server: %v", err)
					}
				}()
			}

			opts = append(opts, signalKaep, signalKasp)
			grpcServer := grpc.NewServer(opts...)

			lis, err := net.Listen("tcp", fmt.Sprintf(":%d", signalPort))
			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}

			proto.RegisterSignalExchangeServer(grpcServer, server.NewServer())
			log.Printf("started server: localhost:%v", signalPort)
			if err := grpcServer.Serve(lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}

			SetupCloseHandler()
			<-stopCh
			log.Println("Receive signal to stop running the Signal server")
		},
	}
)

func init() {
	runCmd.PersistentFlags().IntVar(&signalPort, "port", 10000, "Server port to listen on (e.g. 10000)")
	runCmd.Flags().StringVar(&signalSSLDir, "ssl-dir", "/var/lib/wiretrustee/", "server ssl directory location. *Required only for Let's Encrypt certificates.")
	runCmd.Flags().StringVar(&signalLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
}
