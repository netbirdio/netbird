package server

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	persistentProfilePath = "/etc/netbird/.profile"
	defaultProfilePath    = "/etc/netbird/config.json"
	systemProfilesPath    = "/etc/netbird/profiles"
)

type Profile struct {
	Name string
	Path string
}

type ProfileState struct {
	currentProfile Profile
}

func (p *ProfileState) WritePersistantProfile(profile *Profile) error {
	return os.WriteFile(persistentProfilePath, []byte(profile.Name+"\n"+profile.Path), os.ModePerm)
}

func (p *ProfileState) GetPersistantProfile() (*Profile, error) {
	if _, err := os.Stat(persistentProfilePath); os.IsNotExist(err) {
		return nil, err
	}

	profileBytes, err := os.ReadFile(persistentProfilePath)
	if err != nil {
		return nil, err
	}

	profile := strings.SplitN(string(profileBytes), "\n", 2)

	return &Profile{
		Name: profile[0],
		Path: profile[1],
	}, nil
}

func (p *ProfileState) Init() error {
	currentProfile, err := p.GetPersistantProfile()
	defaultProfile := Profile{"default", defaultProfilePath}

	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		log.Debugln("Current profile couldn't be read due to .profile not existing, using default")

		if err = p.WritePersistantProfile(&defaultProfile); err != nil {
			return err
		}

		p.currentProfile = defaultProfile
		return nil
	}

	p.currentProfile = *currentProfile
	return nil
}

// reconnectAfter disconnects the client until the passed context is cancelled
func reconnectAfter(s *Server, ctx context.Context) error {
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

			<-ctx.Done()

			_, _ = s.Up(ctx, &proto.UpRequest{})
			log.Debugln("reconnecting client after profile switch")
		}()
	}

	return nil
}

func (s *Server) GetProfile(ctx context.Context, req *proto.GetProfileRequest) (*proto.GetProfileResponse, error) {
	return &proto.GetProfileResponse{Profile: s.profileState.currentProfile.Name}, nil
}

func getProfiles(userProfilesPath string) ([]Profile, error) {
	profiles := []Profile{{"default", defaultProfilePath}}

	userProfiles, err := os.ReadDir(userProfilesPath)
	if err != nil {
		return nil, err
	}

	systemProfiles, err := os.ReadDir(systemProfilesPath)
	if err != nil {
		return nil, err
	}

	processProfiles := func(entries []fs.DirEntry) {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			profiles = append(profiles, Profile{
				Name: strings.TrimSuffix(entry.Name(), ".json"),
				Path: path.Join(userProfilesPath, entry.Name()),
			})
		}
	}

	processProfiles(userProfiles)
	processProfiles(systemProfiles)

	return profiles, nil
}

// ListProfiles lists all available profiles
func (s *Server) ListProfiles(ctx context.Context, req *proto.ListProfilesRequest) (*proto.ListProfilesResponse, error) {
	profiles, err := getProfiles(req.UserProfilesPath)
	if err != nil {
		return nil, err
	}

	profileNames := make([]string, len(profiles))

	for i, profile := range profiles {
		profileNames[i] = profile.Name
	}

	return &proto.ListProfilesResponse{Profiles: profileNames}, nil
}

func findProfile(req *proto.SwitchProfileRequest) (*Profile, error) {
	var newProfile *Profile = nil

	profiles, err := getProfiles(req.UserProfilesPath)
	if err != nil {
		return nil, err
	}

	for _, profile := range profiles {
		if profile.Name == req.Profile {
			newProfile = &profile
		}
	}

	if newProfile != nil {
		return newProfile, nil
	}

	if req.IsNewSystemProfile == nil {
		return nil, fmt.Errorf("profile %v does not exist", req.Profile)
	}

	name := req.Profile
	profilePath := path.Join(req.UserProfilesPath, req.Profile+".json")

	if *req.IsNewSystemProfile {
		profilePath = path.Join(systemProfilesPath, req.Profile+".json")
	}

	log.Debugf("Creating new profile %v at %v", name, profilePath)
	return &Profile{Name: name, Path: profilePath}, nil
}

// SwitchProfile switches to a different profile (network)
func (s *Server) SwitchProfile(ctx context.Context, req *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := reconnectAfter(s, ctx); err != nil {
		return nil, err
	}

	newProfile, err := findProfile(req)
	if err != nil {
		return nil, err
	}

	log.Debugf("Reading new config %v from profile %v", newProfile.Path, newProfile.Name)

	configInput := internal.ConfigInput{ConfigPath: newProfile.Path}
	config, err := internal.UpdateOrCreateConfig(configInput)
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()
	s.profileState.currentProfile = *newProfile
	s.latestConfigInput = configInput
	s.config = config
	s.mutex.Unlock()

	if err := s.profileState.WritePersistantProfile(newProfile); err != nil {
		return nil, err
	}

	return &proto.SwitchProfileResponse{}, nil
}
