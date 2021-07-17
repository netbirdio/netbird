package cmd

import (
	"crypto/tls"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	mgmt "github.com/wiretrustee/wiretrustee/management"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	mgmtPort              int
	mgmtDataDir           string
	mgmtLetsencryptDomain string

	kaep = keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	}

	kasp = keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Second,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  5 * time.Second,
		Timeout:               2 * time.Second,
	}

	mgmtCmd = &cobra.Command{
		Use:   "management",
		Short: "start Wiretrustee Management Server",
		Run: func(cmd *cobra.Command, args []string) {
			flag.Parse()

			if _, err := os.Stat(mgmtDataDir); os.IsNotExist(err) {
				err = os.MkdirAll(mgmtDataDir, os.ModeDir)
				log.Fatalf("failed creating datadir: %s: %v", mgmtDataDir, err)
			}

			var opts []grpc.ServerOption

			if mgmtLetsencryptDomain != "" {

				certDir := filepath.Join(mgmtDataDir, "letsencrypt")

				if _, err := os.Stat(certDir); os.IsNotExist(err) {
					err = os.MkdirAll(certDir, os.ModeDir)
					log.Fatalf("failed creating Let's encrypt certdir: %s: %v", certDir, err)
				}

				log.Infof("running with Let's encrypt with domain %s. Cert will be stored in %s", mgmtLetsencryptDomain, certDir)

				certManager := autocert.Manager{
					Prompt:     autocert.AcceptTOS,
					Cache:      autocert.DirCache(certDir),
					HostPolicy: autocert.HostWhitelist(mgmtLetsencryptDomain),
				}
				tls := &tls.Config{GetCertificate: certManager.GetCertificate}

				credentials := credentials.NewTLS(tls)
				opts = append(opts, grpc.Creds(credentials))

				// listener to handle Let's encrypt certificate challenge
				go func() {
					if err := http.Serve(certManager.Listener(), certManager.HTTPHandler(nil)); err != nil {
						log.Fatalf("failed to serve letsencrypt handler: %v", err)
					}
				}()
			}

			opts = append(opts, grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
			grpcServer := grpc.NewServer(opts...)

			server, err := mgmt.NewServer(mgmtDataDir)
			if err != nil {
				log.Fatalf("failed creating new server: %v", err)
			}
			mgmtProto.RegisterManagementServiceServer(grpcServer, server)
			log.Printf("started server: localhost:%v", mgmtPort)

			lis, err := net.Listen("tcp", fmt.Sprintf(":%d", mgmtPort))
			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}

			go func() {
				if err = grpcServer.Serve(lis); err != nil {
					log.Fatalf("failed to serve gRpc server: %v", err)
				}
			}()

			SetupCloseHandler()
			<-stopCh
			log.Println("Receive signal to stop running Management server")
		},
	}
)

func init() {
	mgmtCmd.Flags().IntVar(&mgmtPort, "port", 33073, "server port to listen on")
	mgmtCmd.Flags().StringVar(&mgmtDataDir, "datadir", "/data", "server data directory location")
	mgmtCmd.Flags().StringVar(&mgmtLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")

	mgmtCmd.MarkFlagRequired("port")
	mgmtCmd.MarkFlagRequired("datadir")
}
