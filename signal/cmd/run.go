package cmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
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
		Short: "start Netbird Signal Server daemon",
		Run: func(cmd *cobra.Command, args []string) {
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
	runCmd.PersistentFlags().IntVar(&signalPort, "port", 10000, "Server port to listen on (e.g. 10000)")
	runCmd.Flags().StringVar(&signalSSLDir, "ssl-dir", defaultSignalSSLDir, "server ssl directory location. *Required only for Let's Encrypt certificates.")
	runCmd.Flags().StringVar(&signalLetsencryptDomain, "letsencrypt-domain", "", "a domain to issue Let's Encrypt certificate for. Enables TLS using Let's Encrypt. Will fetch and renew certificate, and run the server with TLS")
}
