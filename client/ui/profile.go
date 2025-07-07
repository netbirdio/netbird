//go:build !(linux && 386)

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"fyne.io/systray"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// showProfilesUI creates and displays the Profiles window with a list of existing profiles,
// a button to add new profiles, allows removal, and lets the user switch the active profile.
func (s *serviceClient) showProfilesUI() {

	profiles, err := s.getProfiles()
	if err != nil {
		log.Errorf("get profiles: %v", err)
		return
	}

	var refresh func()
	// List widget for profiles
	list := widget.NewList(
		func() int { return len(profiles) },
		func() fyne.CanvasObject {
			// Each item: Selected indicator, Name, spacer, Select & Remove buttons
			return container.NewHBox(
				widget.NewLabel(""), // indicator
				widget.NewLabel(""), // profile name
				layout.NewSpacer(),
				widget.NewButton("Select", nil),
				widget.NewButton("Remove", nil),
			)
		},
		func(i widget.ListItemID, item fyne.CanvasObject) {
			// Populate each row
			row := item.(*fyne.Container)
			indicator := row.Objects[0].(*widget.Label)
			nameLabel := row.Objects[1].(*widget.Label)
			selectBtn := row.Objects[3].(*widget.Button)
			removeBtn := row.Objects[4].(*widget.Button)

			profile := profiles[i]
			// Show a checkmark if selected
			if profile.IsActive {
				indicator.SetText("✓")
			} else {
				indicator.SetText("")
			}
			nameLabel.SetText(profile.Name)

			// Configure Select/Active button
			selectBtn.SetText(func() string {
				if profile.IsActive {
					return "Active"
				}
				return "Select"
			}())
			selectBtn.OnTapped = func() {
				if profile.IsActive {
					return // already active
				}
				// confirm switch
				dialog.ShowConfirm(
					"Switch Profile",
					fmt.Sprintf("Are you sure you want to switch to '%s'?", profile.Name),
					func(confirm bool) {
						if !confirm {
							return
						}
						// switch
						err = s.switchProfile(profile.Name)
						if err != nil {
							dialog.ShowError(fmt.Errorf("failed to select profile: %w", err), s.wProfiles)
							return
						}

						dialog.ShowInformation(
							"Profile Switched",
							fmt.Sprintf("Profile '%s' switched successfully", profile.Name),
							s.wProfiles,
						)
						// update slice flags
						refresh()
					},
					s.wProfiles,
				)
			}

			// Remove profile
			removeBtn.SetText("Remove")
			removeBtn.OnTapped = func() {
				dialog.ShowConfirm(
					"Delete Profile",
					fmt.Sprintf("Are you sure you want to delete '%s'?", profile.Name),
					func(confirm bool) {
						if !confirm {
							return
						}
						// remove
						err = s.removeProfile(profile.Name)
						if err != nil {
							dialog.ShowError(fmt.Errorf("failed to remove profile: %w", err), s.wProfiles)
							return
						}
						dialog.ShowInformation(
							"Profile Removed",
							fmt.Sprintf("Profile '%s' removed successfully", profile.Name),
							s.wProfiles,
						)
						// update slice
						refresh()
					},
					s.wProfiles,
				)
			}
		},
	)

	refresh = func() {
		newProfiles, err := s.getProfiles()
		if err != nil {
			dialog.ShowError(err, s.wProfiles)
			return
		}
		profiles = newProfiles // update the slice
		list.Refresh()         // tell Fyne to re-call length/update on every visible row
	}

	// Button to add a new profile
	newBtn := widget.NewButton("New Profile", func() {
		nameEntry := widget.NewEntry()
		nameEntry.SetPlaceHolder("Enter Profile Name")

		formItems := []*widget.FormItem{{Text: "Name:", Widget: nameEntry}}
		dlg := dialog.NewForm(
			"New Profile",
			"Create",
			"Cancel",
			formItems,
			func(confirm bool) {
				if !confirm {
					return
				}
				name := nameEntry.Text
				if name == "" {
					dialog.ShowError(errors.New("profile name cannot be empty"), s.wProfiles)
					return
				}

				// add profile
				err = s.addProfile(name)
				if err != nil {
					dialog.ShowError(fmt.Errorf("failed to create profile: %w", err), s.wProfiles)
					return
				}
				dialog.ShowInformation(
					"Profile Created",
					fmt.Sprintf("Profile '%s' created successfully", name),
					s.wProfiles,
				)
				// update slice
				refresh()
			},
			s.wProfiles,
		)
		// make dialog wider
		dlg.Resize(fyne.NewSize(350, 150))
		dlg.Show()
	})

	// Assemble window content
	content := container.NewBorder(nil, newBtn, nil, nil, list)
	s.wProfiles = s.app.NewWindow("NetBird Profiles")
	s.wProfiles.SetContent(content)
	s.wProfiles.Resize(fyne.NewSize(400, 300))
	s.wProfiles.SetOnClosed(s.cancel)

	s.wProfiles.Show()
}

func (s *serviceClient) addProfile(profileName string) error {
	err := s.profileManager.AddProfile(profilemanager.Profile{
		Name: profileName,
	})

	if err != nil {
		return fmt.Errorf("add profile: %w", err)
	}

	return nil
}

func (s *serviceClient) switchProfile(profileName string) error {
	err := s.profileManager.SwitchProfile(profileName)
	if err != nil {
		return fmt.Errorf("switch profile: %w", err)
	}
	return nil
}

func (s *serviceClient) removeProfile(profileName string) error {
	err := s.profileManager.RemoveProfile(profileName)
	if err != nil {
		return fmt.Errorf("remove profile: %w", err)
	}

	return nil
}

func (s *serviceClient) getProfiles() ([]profilemanager.Profile, error) {
	prof, err := s.profileManager.ListProfiles()
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	return prof, nil
}

type subItem struct {
	*systray.MenuItem
	ctx    context.Context
	cancel context.CancelFunc
}

type profileMenu struct {
	mu                    sync.Mutex
	ctx                   context.Context
	profileManager        *profilemanager.ProfileManager
	eventHandler          eventHandler
	profileMenuItem       *systray.MenuItem
	emailMenuItem         *systray.MenuItem
	profileSubItems       []*subItem
	manageProfilesSubItem *subItem
	profilesState         []profilemanager.Profile
	downClickCallback     func() error
	upClickCallback       func() error
	getSrvClientCallback  func(timeout time.Duration) (proto.DaemonServiceClient, error)
}

func newProfileMenu(ctx context.Context, profileManager *profilemanager.ProfileManager,
	eventHandler eventHandler, profileMenuItem, emailMenuItem *systray.MenuItem,
	downClickCallback, upClickCallback func() error,
	getSrvClientCallback func(timeout time.Duration) (proto.DaemonServiceClient, error)) *profileMenu {
	p := profileMenu{
		ctx:                  ctx,
		profileManager:       profileManager,
		eventHandler:         eventHandler,
		profileMenuItem:      profileMenuItem,
		emailMenuItem:        emailMenuItem,
		downClickCallback:    downClickCallback,
		upClickCallback:      upClickCallback,
		getSrvClientCallback: getSrvClientCallback,
	}

	p.emailMenuItem.Disable()
	p.emailMenuItem.Hide()
	p.refresh()
	go p.updateMenu()

	return &p
}

func (p *profileMenu) refresh() {
	p.mu.Lock()
	defer p.mu.Unlock()

	profiles, err := p.profileManager.ListProfiles()
	if err != nil {
		log.Errorf("failed to list profiles: %v", err)
		return
	}

	// Clear existing profile items
	for _, item := range p.profileSubItems {
		item.Remove()
		item.cancel()
	}
	p.profileSubItems = make([]*subItem, 0, len(profiles))
	p.profilesState = profiles

	if p.manageProfilesSubItem != nil {
		// Remove the manage profiles item if it exists
		p.manageProfilesSubItem.Remove()
		p.manageProfilesSubItem.cancel()
		p.manageProfilesSubItem = nil
	}

	activeProfState, err := p.profileManager.GetActiveProfileState()
	if err != nil {
		log.Warnf("failed to get active profile state: %v", err)
		p.emailMenuItem.Hide()
	} else if activeProfState.Email != "" {
		p.emailMenuItem.SetTitle(fmt.Sprintf("(%s)", activeProfState.Email))
		p.emailMenuItem.Show()
	}

	var activeProfile *profilemanager.Profile
	for _, profile := range profiles {
		item := p.profileMenuItem.AddSubMenuItem(profile.Name, "")
		if profile.IsActive {
			item.Check()
			activeProfile = &profile
		}

		ctx, cancel := context.WithCancel(context.Background())
		p.profileSubItems = append(p.profileSubItems, &subItem{item, ctx, cancel})

		go func() {
			for {
				select {
				case <-ctx.Done():
					return // context cancelled
				case _, ok := <-item.ClickedCh:
					if !ok {
						return // channel closed
					}

					// Handle profile selection
					if profile.IsActive {
						log.Infof("Profile '%s' is already active", profile.Name)
						return
					}
					err := p.profileManager.SwitchProfile(profile.Name)
					if err != nil {
						log.Errorf("failed to switch profile '%s': %v", profile.Name, err)
						return
					}
					log.Infof("Switched to profile '%s'", profile.Name)
					conn, err := p.getSrvClientCallback(defaultFailTimeout)
					if err != nil {
						log.Errorf("failed to get daemon client: %v", err)
						return
					}

					status, err := conn.Status(ctx, &proto.StatusRequest{})
					if err != nil {
						log.Errorf("failed to get status after switching profile: %v", err)
						return
					}

					if status.Status == string(internal.StatusConnected) {
						if err := p.downClickCallback(); err != nil {
							log.Errorf("failed to handle down click after switching profile: %v", err)
						}
					}

					if err := p.upClickCallback(); err != nil {
						log.Errorf("failed to handle up click after switching profile: %v", err)
					}
					p.refresh()
				}
			}
		}()

	}
	p.profileMenuItem.AddSeparator()
	ctx, cancel := context.WithCancel(context.Background())
	manageItem := p.profileMenuItem.AddSubMenuItem("Manage Profiles", "")
	p.manageProfilesSubItem = &subItem{manageItem, ctx, cancel}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return // context cancelled
			case _, ok := <-manageItem.ClickedCh:
				if !ok {
					return // channel closed
				}
				// Handle manage profiles click
				p.eventHandler.runSelfCommand(p.ctx, "profiles", "true")
				p.refresh()
			}
		}
	}()

	if activeProfile != nil {
		p.profileMenuItem.SetTitle(activeProfile.Name)
	} else {
		p.profileMenuItem.SetTitle("Profile: None")
		p.emailMenuItem.Hide()
	}

}

func (p *profileMenu) updateMenu() {
	// check every second
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:

			// get profilesList
			profiles, err := p.profileManager.ListProfiles()
			if err != nil {
				log.Errorf("failed to list profiles: %v", err)
				continue
			}

			sort.Slice(profiles, func(i, j int) bool {
				return profiles[i].Name < profiles[j].Name
			})

			p.mu.Lock()
			state := p.profilesState
			p.mu.Unlock()

			sort.Slice(state, func(i, j int) bool {
				return state[i].Name < state[j].Name
			})

			if slices.Equal(profiles, state) {
				continue
			}

			p.refresh()
		case <-p.ctx.Done():
			return // context cancelled

		}
	}
}
