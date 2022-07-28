package cmd

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	httpapi "github.com/netbirdio/netbird/management/server/http"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"io"
	"io/fs"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server"
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
		Short: "start NetBird Management Server",
		RunE: func(cmd *cobra.Command, args []string) error {
			flag.Parse()
			err := util.InitLog(logLevel, logFile)
			if err != nil {
				return fmt.Errorf("failed initializing log %v", err)
			}

			err = handleRebrand(cmd)
			if err != nil {
				return fmt.Errorf("failed to migrate files %v", err)
			}

			config, err := loadMgmtConfig(mgmtConfig)
			if err != nil {
				return fmt.Errorf("failed reading provided config file: %s: %v", mgmtConfig, err)
			}

			if _, err = os.Stat(config.Datadir); os.IsNotExist(err) {
				err = os.MkdirAll(config.Datadir, os.ModeDir)
				if err != nil {
					return fmt.Errorf("failed creating datadir: %s: %v", config.Datadir, err)
				}
			}

			store, err := server.NewStore(config.Datadir)
			if err != nil {
				return fmt.Errorf("failed creating Store: %s: %v", config.Datadir, err)
			}
			peersUpdateManager := server.NewPeersUpdateManager()

			var idpManager idp.Manager
			if config.IdpManagerConfig != nil {
				idpManager, err = idp.NewManager(*config.IdpManagerConfig)
				if err != nil {
					return fmt.Errorf("failed retrieving a new idp manager with err: %v", err)
				}
			}

			accountManager, err := server.BuildManager(store, peersUpdateManager, idpManager)
			if err != nil {
				return fmt.Errorf("failed to build default manager: %v", err)
			}

			turnManager := server.NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig)

			gRPCOpts := []grpc.ServerOption{grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp)}
			var certManager *autocert.Manager
			var tlsConfig *tls.Config
			tlsEnabled := false
			if config.HttpConfig.LetsEncryptDomain != "" {
				certManager, err = encryption.CreateCertManager(config.Datadir, config.HttpConfig.LetsEncryptDomain)
				if err != nil {
					return fmt.Errorf("failed creating LetsEncrypt cert manager: %v", err)
				}
				transportCredentials := credentials.NewTLS(certManager.TLSConfig())
				gRPCOpts = append(gRPCOpts, grpc.Creds(transportCredentials))
				tlsEnabled = true
			} else if config.HttpConfig.CertFile != "" && config.HttpConfig.CertKey != "" {
				tlsConfig, err = loadTLSConfig(config.HttpConfig.CertFile, config.HttpConfig.CertKey)
				if err != nil {
					log.Errorf("cannot load TLS credentials: %v", err)
					return err
				}
				transportCredentials := credentials.NewTLS(tlsConfig)
				gRPCOpts = append(gRPCOpts, grpc.Creds(transportCredentials))
				tlsEnabled = true
			}

			httpAPIHandler, err := httpapi.APIHandler(accountManager,
				config.HttpConfig.AuthIssuer, config.HttpConfig.AuthAudience, config.HttpConfig.AuthKeysLocation)
			if err != nil {
				return fmt.Errorf("failed creating HTTP API handler: %v", err)
			}

			gRPCAPIHandler := grpc.NewServer(gRPCOpts...)
			srv, err := server.NewServer(config, accountManager, peersUpdateManager, turnManager)
			if err != nil {
				return fmt.Errorf("failed creating gRPC API handler: %v", err)
			}
			mgmtProto.RegisterManagementServiceServer(gRPCAPIHandler, srv)

			rootHandler := handlerFunc(gRPCAPIHandler, httpAPIHandler)
			var listener net.Listener
			if certManager != nil {
				rootHandler = certManager.HTTPHandler(rootHandler)
				listener = certManager.Listener()
				log.Infof("running HTTP (LetsEncrypt challenge handler): %s", listener.Addr().String())
			} else if tlsConfig != nil {
				listener, err = tls.Listen("tcp", fmt.Sprintf(":%d", mgmtPort), tlsConfig)
				if err != nil {
					return fmt.Errorf("failed creating TLS listener on port %d: %v", mgmtPort, err)
				}
			} else {
				listener, err = net.Listen("tcp", fmt.Sprintf(":%d", mgmtPort))
				if err != nil {
					return fmt.Errorf("failed creating TCP listener on port %d: %v", mgmtPort, err)
				}
			}

			serveHTTP(listener, rootHandler, tlsEnabled)

			SetupCloseHandler()

			<-stopCh
			_ = listener.Close()
			gRPCAPIHandler.Stop()
			log.Infof("stopped Management Service")

			return nil
		},
	}
)

func serveHTTP(listener net.Listener, handler http.Handler, tlsEnabled bool) {
	log.Infof("running HTTP server and gRPC server on the same port: %s", listener.Addr().String())
	go func() {
		var err error
		if tlsEnabled {
			err = http.Serve(listener, handler)
		} else {
			// the following magic is needed to support HTTP2 without TLS
			// and still share a single port between gRPC and HTTP APIs
			h1s := &http.Server{
				Handler: h2c.NewHandler(handler, &http2.Server{}),
			}
			err = h1s.Serve(listener)
		}

		if err != nil {
			select {
			case stopCh <- 1:
				log.Errorf("failed to serve https server: %v", err)
			default:
				// stop has been already called, nothing to report
			}
		}
	}()
}

func createGRPCServer(opts []grpc.ServerOption, peersUpdateManager *server.PeersUpdateManager, config *server.Config,
	accountManager server.AccountManager) (*grpc.Server, error) {
	grpcServer := grpc.NewServer(opts...)
	turnManager := server.NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig)
	srv, err := server.NewServer(config, accountManager, peersUpdateManager, turnManager)
	if err != nil {
		log.Errorf("failed creating new server: %v", err)
		return nil, err
	}
	mgmtProto.RegisterManagementServiceServer(grpcServer, srv)
	return grpcServer, nil
}

func handlerFunc(gRPCHandler *grpc.Server, httpHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		grpcHeader := strings.HasPrefix(request.Header.Get("Content-Type"), "application/grpc") ||
			strings.HasPrefix(request.Header.Get("Content-Type"), "application/grpc+proto")
		fmt.Println(grpcHeader)
		if request.ProtoMajor == 2 && grpcHeader {
			gRPCHandler.ServeHTTP(writer, request)
		} else {
			httpHandler.ServeHTTP(writer, request)
		}
	})
}

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

func handleRebrand(cmd *cobra.Command) error {
	var err error
	if logFile == defaultLogFile {
		if migrateToNetbird(oldDefaultLogFile, defaultLogFile) {
			cmd.Printf("will copy Log dir %s and its content to %s\n", oldDefaultLogDir, defaultLogDir)
			err = cpDir(oldDefaultLogDir, defaultLogDir)
			if err != nil {
				return err
			}
		}
	}
	if mgmtConfig == defaultMgmtConfig {
		if migrateToNetbird(oldDefaultMgmtConfig, defaultMgmtConfig) {
			cmd.Printf("will copy Config dir %s and its content to %s\n", oldDefaultMgmtConfigDir, defaultMgmtConfigDir)
			err = cpDir(oldDefaultMgmtConfigDir, defaultMgmtConfigDir)
			if err != nil {
				return err
			}
		}
	}
	if mgmtDataDir == defaultMgmtDataDir {
		if migrateToNetbird(oldDefaultMgmtDataDir, defaultMgmtDataDir) {
			cmd.Printf("will copy Config dir %s and its content to %s\n", oldDefaultMgmtDataDir, defaultMgmtDataDir)
			err = cpDir(oldDefaultMgmtDataDir, defaultMgmtDataDir)
			if err != nil {
				return err
			}
		}
	}
	return nil
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
	_, errOld := os.Stat(oldPath)
	_, errNew := os.Stat(newPath)

	if errors.Is(errOld, fs.ErrNotExist) || errNew == nil {
		return false
	}

	return true
}
