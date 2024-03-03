package cmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

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
	signalLetsencryptDomain string
	signalSSLDir            string
	defaultSignalSSLDir     string
	tlsEnabled              bool

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
		Short: "start NetBird Signal Server daemon",
		PreRun: func(cmd *cobra.Command, args []string) {
			// detect whether user specified a port
			userPort := cmd.Flag("port").Changed
			if signalLetsencryptDomain != "" {
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

			err := util.InitLog(logLevel, logFile)
			if err != nil {
				log.Fatalf("failed initializing log %v", err)
			}

			if signalSSLDir == "" {
				oldPath := "/var/lib/wiretrustee"
				if migrateToNetbird(oldPath, defaultSignalSSLDir) {
					if err := cpDir(oldPath, defaultSignalSSLDir); err != nil {
						log.Fatal(err)
					}
				}
			}

			var opts []grpc.ServerOption
			var certManager *autocert.Manager
			if tlsEnabled {
				// Let's encrypt enabled -> generate certificate automatically
				certManager, err = encryption.CreateCertManager(signalSSLDir, signalLetsencryptDomain)
				if err != nil {
					return err
				}
				transportCredentials := credentials.NewTLS(certManager.TLSConfig())
				opts = append(opts, grpc.Creds(transportCredentials))
			}

			opts = append(opts, signalKaep, signalKasp)
			grpcServer := grpc.NewServer(opts...)
			proto.RegisterSignalExchangeServer(grpcServer, server.NewServer())

			var compatListener net.Listener
			if signalPort != 10000 {
				// The Signal gRPC server was running on port 10000 previously. Old agents that are already connected to Signal
				// are using port 10000. For compatibility purposes we keep running a 2nd gRPC server on port 10000.
				compatListener, err = serveGRPC(grpcServer, 10000)
				if err != nil {
					return err
				}
				log.Infof("running gRPC backward compatibility server: %s", compatListener.Addr().String())
			}

			var grpcListener net.Listener
			var httpListener net.Listener
			if tlsEnabled {
				httpListener = certManager.Listener()
				if signalPort == 443 {
					// running gRPC and HTTP cert manager on the same port
					serveHTTP(httpListener, certManager.HTTPHandler(grpcHandlerFunc(grpcServer)))
					log.Infof("running HTTP server (LetsEncrypt challenge handler) and gRPC server on the same port: %s", httpListener.Addr().String())
				} else {
					serveHTTP(httpListener, certManager.HTTPHandler(nil))
					log.Infof("running HTTP server (LetsEncrypt challenge handler): %s", httpListener.Addr().String())
				}
			}

			if signalPort != 443 || !tlsEnabled {
				grpcListener, err = serveGRPC(grpcServer, signalPort)
				if err != nil {
					return err
				}
				log.Infof("running gRPC server: %s", grpcListener.Addr().String())
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
			log.Infof("stopped Signal Service")

			return nil
		},
	}
)

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
	var fds []os.DirEntry
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}

	if fds, err = os.ReadDir(src); err != nil {
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

func init() {
	runCmd.PersistentFlags().IntVar(&signalPort, "port", 80, "Server port to listen on (defaults to 443 if TLS is enabled, 80 otherwise")
	runCmd.Flags().StringVar(&signalSSLDir, "ssl-dir", defaultSignalSSLDir, "server ssl directory location. *Required only for Let's Encrypt certificates.")
	runCmd.Flags().StringVar(&signalLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
}
