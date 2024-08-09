package server

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

// EnsureDefaultProfile make the config a symlink to the profiles/default.json should it not exists,
// making the current config the default profile
// Cancelling the context passed will reconnect the client
// Can be cancelled directly after EnsureDefaultProfile, given that no further changes to the profile are required
func EnsureDefaultProfile(s *Server, ctx context.Context) error {
	configPath := s.latestConfigInput.ConfigPath
	profilesPath := path.Join(path.Dir(configPath), "profiles")
	defaultPath := path.Join(profilesPath, "default.json")

	if err := os.MkdirAll(profilesPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create profiles directory: %v", err)
	}

	log.Debugln("ensuring default profile exists")

	resp, err := s.Status(ctx, &proto.StatusRequest{GetFullPeerStatus: false})
	if err != nil {
		return err
	}

	if resp.GetStatus() == string(internal.StatusConnected) ||
		resp.GetStatus() == string(internal.StatusConnecting) {
		log.Debugln("client is connected, disconnecting")

		go func() {
			// TODO: Handle these errors, somehow
			res, err := s.Down(ctx, &proto.DownRequest{})
			log.Debugf("disconnected client due to profile switch: %v %v", res, err)

			time.Sleep(7 * time.Second)

			select {
			case <-ctx.Done():
				_, _ = s.Up(ctx, &proto.UpRequest{})
				log.Debugln("reconnecting client after profile switch")
			}
		}()
	}

	if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
		if err := os.Rename(configPath, defaultPath); err != nil {
			return fmt.Errorf("failed to move config.json to default.json: %v", err)
		}

		// Create a symlink to the default profile
		if err := os.Symlink(defaultPath, configPath); err != nil {
			return fmt.Errorf("failed to create symlink to default profile: %v", err)
		}
	}

	return nil
}

func (s *Server) GetProfile(ctx context.Context, req *proto.GetProfileRequest) (*proto.GetProfileResponse, error) {
	profile := "default"

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := EnsureDefaultProfile(s, ctx); err != nil {
		return nil, err
	}

	configPath := s.latestConfigInput.ConfigPath

	realPath, err := filepath.EvalSymlinks(configPath)
	if err != nil {
		return nil, fmt.Errorf("Couldn't read config at %v", configPath)
	}

	if realPath != configPath {
		profile = strings.TrimSuffix(path.Base(realPath), ".json")
	}

	return &proto.GetProfileResponse{Profile: profile}, nil
}

// ListProfiles lists all available profiles
func (s *Server) ListProfiles(ctx context.Context, req *proto.ListProfilesRequest) (*proto.ListProfilesResponse, error) {
	profiles := []string{}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := EnsureDefaultProfile(s, ctx); err != nil {
		return nil, err
	}

	configPath := s.latestConfigInput.ConfigPath
	profilesPath := path.Join(path.Dir(configPath), "profiles")

	entries, err := os.ReadDir(profilesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read profiles directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".json")
		profiles = append(profiles, name)
	}

	return &proto.ListProfilesResponse{Profiles: profiles}, nil
}

// SwitchProfile switches to a different profile (network)
func (s *Server) SwitchProfile(ctx context.Context, req *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := EnsureDefaultProfile(s, ctx); err != nil {
		return nil, err
	}

	configPath := s.latestConfigInput.ConfigPath
	profilePath := path.Join(path.Join(path.Dir(configPath), "profiles"), req.Profile+".json")

	log.Debugf("replacing config at %v with config at %v", configPath, profilePath)

	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("profile %v (%v) does not exist", req.Profile, profilePath)
	}

	if err := os.Remove(configPath); err != nil {
		return nil, fmt.Errorf("failed to remove old profile: %v", err)
	}

	if err := os.Symlink(profilePath, configPath); err != nil {
		return nil, fmt.Errorf("failed to copy new profile %v: %v", req.Profile, err)
	}

	config, err := internal.UpdateOrCreateConfig(internal.ConfigInput{ConfigPath: configPath})
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()
	s.config = config
	s.mutex.Unlock()

	return &proto.SwitchProfileResponse{}, nil
}
