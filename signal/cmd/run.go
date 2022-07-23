package cmd

import (
	"errors"
	"flag"
	"fmt"
	"github.com/soheilhy/cmux"
	"golang.org/x/crypto/acme/autocert"
	"io"
	"io/fs"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/util"
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
			var listener net.Listener
			var certManager *autocert.Manager
			// Let's encrypt enabled -> generate certificate automatically
			if signalLetsencryptDomain != "" {
				certManager, err = encryption.CreateCertManager(signalSSLDir, signalLetsencryptDomain)
				if err != nil {
					return err
				}
				transportCredentials := credentials.NewTLS(certManager.TLSConfig())
				opts = append(opts, grpc.Creds(transportCredentials))

				listener = certManager.Listener()
				log.Infof("HTTP server listening on %s", listener.Addr())
			} else {
				listener, err = net.Listen("tcp", fmt.Sprintf(":%d", signalPort))
				if err != nil {
					return err
				}
			}

			cMux := cmux.New(listener)
			grpcListener := cMux.MatchWithWriters(
				cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"),
				cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc+proto"),
			)
			httpListener := cMux.Match(cmux.HTTP1())

			opts = append(opts, signalKaep, signalKasp)
			grpcServer := grpc.NewServer(opts...)
			proto.RegisterSignalExchangeServer(grpcServer, server.NewServer())

			go grpcServer.Serve(grpcListener)
			if certManager != nil {
				go http.Serve(httpListener, certManager.HTTPHandler(nil))
			}

			log.Infof("started Signal Service: %v", grpcListener.Addr())

			SetupCloseHandler()

			err = cMux.Serve()
			if err != nil {
				return err
			}

			<-stopCh
			_ = listener.Close()
			log.Infof("stopped Signal Service")

			return nil
		},
	}
)

// grpcHandlerFunc returns a http.Handler that delegates to grpcServer on incoming gRPC
func grpcHandlerFunc(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO(tamird): point to merged gRPC code rather than a PR.
		// This is a partial recreation of gRPC's internal checks https://github.com/grpc/grpc-go/pull/514/files#diff-95e9a25b738459a2d3030e1e6fa2a718R61
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
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

func init() {
	runCmd.PersistentFlags().IntVar(&signalPort, "port", 80, "Server port to listen on (e.g. 80)")
	runCmd.Flags().StringVar(&signalSSLDir, "ssl-dir", defaultSignalSSLDir, "server ssl directory location. *Required only for Let's Encrypt certificates.")
	runCmd.Flags().StringVar(&signalLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
}
