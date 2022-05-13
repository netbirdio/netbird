package cmd

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"time"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/util"

	"github.com/netbirdio/netbird/encryption"
	mgmtProto "github.com/netbirdio/netbird/management/proto"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

var (
	mgmtPort              int
	defaultMgmtDataDir    string
	defaultMgmtConfig     string
	mgmtDataDir           string
	mgmtConfig            string
	mgmtLetsencryptDomain string
	certFile              string
	certKey               string

	kaep = keepalive.EnforcementPolicy{
		MinTime:             15 * time.Second,
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
		Short: "start Netbird Management Server",
		Run: func(cmd *cobra.Command, args []string) {
			flag.Parse()
			err := util.InitLog(logLevel, logFile)
			if err != nil {
				log.Fatalf("failed initializing log %v", err)
			}

			if mgmtDataDir == "" {
				oldPath := "/var/lib/wiretrustee"
				newPath := "/var/lib/netbird"
				if migrateToNetbird(oldPath, newPath) {
					if err := cpDir(oldPath, newPath); err != nil {
						log.Fatal(err)
					}
				}
			}

			actualMgmtConfigPath := mgmtConfig
			if mgmtConfig == "" {
				oldPath := "/etc/wiretrustee/management.json"
				if migrateToNetbird(oldPath, defaultMgmtConfig) {
					if err := cpDir("/etc/wiretrustee/", "/etc/netbird/"); err != nil {
						log.Fatal(err)
					}

					if err := cpFile(oldPath, defaultMgmtConfig); err != nil {
						log.Fatal(err)
					}
				}
				actualMgmtConfigPath = defaultMgmtConfig
			}

			config, err := loadMgmtConfig(actualMgmtConfigPath)
			if err != nil {
				log.Fatalf("failed reading provided config file: %s: %v", actualMgmtConfigPath, err)
			}

			if _, err = os.Stat(config.Datadir); os.IsNotExist(err) {
				err = os.MkdirAll(config.Datadir, os.ModeDir)
				if err != nil {
					log.Fatalf("failed creating datadir: %s: %v", config.Datadir, err)
				}
			}

			store, err := server.NewStore(config.Datadir)
			if err != nil {
				log.Fatalf("failed creating a store: %s: %v", config.Datadir, err)
			}
			peersUpdateManager := server.NewPeersUpdateManager()

			var idpManager idp.Manager
			if config.IdpManagerConfig != nil {
				idpManager, err = idp.NewManager(*config.IdpManagerConfig)
				if err != nil {
					log.Fatalln("failed retrieving a new idp manager with err: ", err)
				}
			}

			accountManager := server.NewManager(store, peersUpdateManager, idpManager)

			var opts []grpc.ServerOption

			var httpServer *http.Server
			if config.HttpConfig.LetsEncryptDomain != "" {
				//automatically generate a new certificate with Let's Encrypt
				certManager := encryption.CreateCertManager(config.Datadir, config.HttpConfig.LetsEncryptDomain)
				transportCredentials := credentials.NewTLS(certManager.TLSConfig())
				opts = append(opts, grpc.Creds(transportCredentials))

				httpServer = http.NewHttpsServer(config.HttpConfig, certManager, accountManager)
			} else if config.HttpConfig.CertFile != "" && config.HttpConfig.CertKey != "" {
				//use provided certificate
				tlsConfig, err := loadTLSConfig(config.HttpConfig.CertFile, config.HttpConfig.CertKey)
				if err != nil {
					log.Fatal("cannot load TLS credentials: ", err)
				}
				transportCredentials := credentials.NewTLS(tlsConfig)
				opts = append(opts, grpc.Creds(transportCredentials))
				httpServer = http.NewHttpsServerWithTLSConfig(config.HttpConfig, tlsConfig, accountManager)
			} else {
				//start server without SSL
				httpServer = http.NewHttpServer(config.HttpConfig, accountManager)
			}

			opts = append(opts, grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
			grpcServer := grpc.NewServer(opts...)
			turnManager := server.NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig)
			server, err := server.NewServer(config, accountManager, peersUpdateManager, turnManager)
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

			go func() {
				err = httpServer.Start()
				if err != nil {
					log.Fatalf("failed to serve http server: %v", err)
				}
			}()

			SetupCloseHandler()
			<-stopCh
			log.Println("Receive signal to stop running Management server")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err = httpServer.Stop(ctx)
			if err != nil {
				log.Fatalf("failed stopping the http server %v", err)
			}

			grpcServer.Stop()
		},
	}
)

func loadMgmtConfig(mgmtConfigPath string) (*server.Config, error) {
	config := &server.Config{}
	_, err := util.ReadJson(mgmtConfigPath, config)
	if err != nil {
		return nil, err
	}
	if mgmtLetsencryptDomain != "" {
		config.HttpConfig.LetsEncryptDomain = mgmtLetsencryptDomain
	}
	if mgmtDataDir != "" {
		config.Datadir = mgmtDataDir
	}

	if certKey != "" && certFile != "" {
		config.HttpConfig.CertFile = certFile
		config.HttpConfig.CertKey = certKey
	}

	return config, err
}

func loadTLSConfig(certFile string, certKey string) (*tls.Config, error) {
	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(certFile, certKey)
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	return config, nil
}

func cpFile(src, dst string) error {
	var err error
	var srcfd *os.File
	var dstfd *os.File
	var srcinfo os.FileInfo

	if srcfd, err = os.Open(src); err != nil {
		return err
	}
	defer srcfd.Close()

	if dstfd, err = os.Create(dst); err != nil {
		return err
	}
	defer dstfd.Close()

	if _, err = io.Copy(dstfd, srcfd); err != nil {
		return err
	}
	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}
	return os.Chmod(dst, srcinfo.Mode())
}

func copySymLink(source, dest string) error {
	link, err := os.Readlink(source)
	if err != nil {
		return err
	}
	return os.Symlink(link, dest)
}

func cpDir(src string, dst string) error {
	var err error
	var fds []os.FileInfo
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}

	if fds, err = ioutil.ReadDir(src); err != nil {
		return err
	}
	for _, fd := range fds {
		srcfp := path.Join(src, fd.Name())
		dstfp := path.Join(dst, fd.Name())

		fileInfo, err := os.Stat(srcfp)
		if err != nil {
			log.Fatalf("Couldn't get fileInfo; %v", err)
		}

		switch fileInfo.Mode() & os.ModeType {
		case os.ModeSymlink:
			if err = copySymLink(srcfp, dstfp); err != nil {
				log.Fatalf("Failed to copy from %s to %s; %v", srcfp, dstfp, err)
			}
		case os.ModeDir:
			if err = cpDir(srcfp, dstfp); err != nil {
				log.Fatalf("Failed to copy from %s to %s; %v", srcfp, dstfp, err)
			}
		default:
			if err = cpFile(srcfp, dstfp); err != nil {
				log.Fatalf("Failed to copy from %s to %s; %v", srcfp, dstfp, err)
			}
		}
	}
	return nil
}

func migrateToNetbird(oldPath, newPath string) bool {
	_, old := os.Stat(oldPath)
	_, new := os.Stat(newPath)

	if os.IsNotExist(old) || os.IsExist(new) {
		return false
	}

	return true
}

func init() {
	mgmtCmd.Flags().IntVar(&mgmtPort, "port", 33073, "server port to listen on")
	mgmtCmd.Flags().StringVar(&mgmtDataDir, "datadir", defaultMgmtDataDir, "server data directory location")
	mgmtCmd.Flags().StringVar(&mgmtConfig, "config", defaultMgmtConfig, "Netbird config file location. Config params specified via command line (e.g. datadir) have a precedence over configuration from this file")
	mgmtCmd.Flags().StringVar(&mgmtLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
	mgmtCmd.Flags().StringVar(&certFile, "cert-file", "", "Location of your SSL certificate. Can be used when you have an existing certificate and don't want a new certificate be generated automatically. If letsencrypt-domain is specified this property has no effect")
	mgmtCmd.Flags().StringVar(&certKey, "cert-key", "", "Location of your SSL certificate private key. Can be used when you have an existing certificate and don't want a new certificate be generated automatically. If letsencrypt-domain is specified this property has no effect")
	rootCmd.MarkFlagRequired("config") //nolint

}
