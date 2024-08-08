package cmd

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/spf13/cobra"
)

func stopServiceIfRunning(cmd *cobra.Command) (func() error, error) {
	s, err := newSVC(newProgram(context.WithCancel(cmd.Context())), newSVCConfig())
	if err != nil {
		return nil, err
	}

	status, err := s.Status()
	if err != nil {
		return nil, err
	}

	if status == service.StatusRunning {
		if err := s.Stop(); err != nil {
			return nil, err
		}

		return s.Start, nil
	}

	return func() error { return nil }, nil
}

func disconnectClientIfConnected(cmd *cobra.Command) error {
	ctx := internal.CtxInitState(cmd.Context())

	resp, err := getStatus(ctx)
	if err != nil {
		return err
	}

	if resp.GetStatus() == string(internal.StatusConnected) || resp.GetStatus() == string(internal.StatusConnecting) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*7)
		defer cancel()

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to service CLI interface %v", err)
		}

		defer conn.Close()

		daemonClient := proto.NewDaemonServiceClient(conn)

		if _, err := daemonClient.Down(ctx, &proto.DownRequest{}); err != nil {
			return fmt.Errorf("call service down method: %v", err)
		}
	}

	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func ensureDefaultProfile(profilesPath string) (bool, error) {
	defaultPath := path.Join(profilesPath, "default.json")

	if !exists(defaultPath) {
		if err := os.Rename(configPath, defaultPath); err != nil {
			return false, fmt.Errorf("failed to move config.json to default.json: %v", err)
		}

		// Create a symlink to the default profile
		if err := os.Symlink(defaultPath, configPath); err != nil {
			return false, fmt.Errorf("failed to create symlink to default profile: %v", err)
		}

		return true, nil
	}

	return false, nil
}

func getProfilesPath() (string, error) {
	profilesPath := path.Join(defaultConfigPathDir, "profiles")

	if err := os.MkdirAll(profilesPath, os.ModePerm); err != nil {
		return "", fmt.Errorf("failed to create profiles directory: %v", err)
	}

	return profilesPath, nil
}

func switchProfile(cmd *cobra.Command, args []string) error {
	profilesPath, err := getProfilesPath()
	if err != nil {
		return err
	}

	if err := disconnectClientIfConnected(cmd); err != nil {
		return err
	}

	start, err := stopServiceIfRunning(cmd)
	if err != nil {
		return err
	}

	if _, err := ensureDefaultProfile(profilesPath); err != nil {
		return err
	}

	profilePath := path.Join(profilesPath, args[0]+".json")
	if !exists(profilePath) {
		return fmt.Errorf("profile %v (%v) does not exist", args[0], profilePath)
	}

	if err := os.Remove(configPath); err != nil {
		return fmt.Errorf("failed to remove old profile: %v", err)
	}

	if err := os.Symlink(profilePath, configPath); err != nil {
		return fmt.Errorf("failed to copy new profile %v: %v", args[0], err)
	}

	if err := start(); err != nil {
		return err
	}

	return nil
}

var (
	profileCmd = &cobra.Command{
		Use:   "profile [newProfile]",
		Short: "switch to profile newProfile or get the current one",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (len(args)) == 1 {
				return switchProfile(cmd, args)
			}

			realPath, err := filepath.EvalSymlinks(configPath)
			if err != nil {
				return fmt.Errorf("Couldn't read config at %v", configPath)
			}

			// The config is not symlinked, ensure the default profile exists
			if realPath == configPath {
				cmd.Println("default")

				profilesPath, err := getProfilesPath()
				if err != nil {
					return err
				}

				if err := disconnectClientIfConnected(cmd); err != nil {
					return err
				}

				start, err := stopServiceIfRunning(cmd)
				if err != nil {
					return err
				}

				if _, err := ensureDefaultProfile(profilesPath); err != nil {
					return err
				}

				if err := start(); err != nil {
					return err
				}
			}

			profile := strings.TrimSuffix(path.Base(realPath), ".json")
			cmd.Println(profile)

			return nil
		},
	}

	profilesCmd = &cobra.Command{
		Use:   "profiles",
		Short: "list all profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			ensureProfileErr := make(chan error)

			profilesPath, err := getProfilesPath()
			if err != nil {
				return err
			}

			// Defer this so the profiles are displayed without the service stopping
			// blocking the thread
			go func() {
				shouldRestart, err := ensureDefaultProfile(profilesPath)

				if err != nil {
					ensureProfileErr <- err
					return
				}

				if shouldRestart {
					if err := disconnectClientIfConnected(cmd); err != nil {
						ensureProfileErr <- err
						return
					}

					start, err := stopServiceIfRunning(cmd)
					if err != nil {
						ensureProfileErr <- err
						return
					}

					if err := start(); err != nil {
						ensureProfileErr <- err
						return
					}
				}

				ensureProfileErr <- nil
			}()

			defer close(ensureProfileErr)

			entries, err := os.ReadDir(profilesPath)
			if err != nil {
				return fmt.Errorf("failed to read profiles directory: %v", err)
			}

			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}

				cmd.Println(strings.TrimSuffix(entry.Name(), ".json"))
			}

			if err := <-ensureProfileErr; err != nil {
				return err
			}

			return nil
		},
	}
)
