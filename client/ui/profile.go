package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// showProfilesUI creates and displays the Profiles window with a list of existing profiles,
// a button to add new profiles, allows removal, and lets the user switch the active profile.
func (s *serviceClient) showProfilesUI() {
	mProfiles := newProfileMenu()

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

						conn, err := s.getSrvClient(defaultFailTimeout)
						if err != nil {
							log.Errorf("get client: %v", err)
							return
						}
						// switch
						err = mProfiles.switchProfile(s.ctx, conn, profile.Name)
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

type profileMenu struct {
	mtx      sync.Mutex
	profiles []*proto.Profile
}

type profile struct {
	name     string
	selected bool
}

func newProfileMenu() *profileMenu {
	p := &profileMenu{
		profiles: make([]*proto.Profile, 0),
	}
	return p
}

func (p *profileMenu) clearProfiles() {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.profiles = make([]*proto.Profile, 0)
}

// func (p *profileMenu) updateProfiles(ctx context.Context, conn proto.DaemonServiceClient) {
// 	profiles, err := p.getProfiles(ctx, conn)
// 	if err != nil {
// 		log.Errorf("get profiles: %v", err)
// 		return
// 	}

// 	// Clear existing profiles
// 	p.clearProfiles()

// 	p.mtx.Lock()
// 	defer p.mtx.Unlock()
// 	// Add new profiles
// 	p.profiles = append(p.profiles, profiles...)

// }

func (s *serviceClient) addProfile(profileName string) error {
	err := s.profileManager.AddProfile(profilemanager.Profile{
		Name: profileName,
	})

	if err != nil {
		return fmt.Errorf("add profile: %w", err)
	}

	return nil
}

func (p *profileMenu) switchProfile(pCtx context.Context, conn proto.DaemonServiceClient, profileName string) error {
	ctx, cancel := context.WithTimeout(pCtx, defaultFailTimeout)
	defer cancel()

	resp, err := conn.SwitchProfile(ctx, &proto.SwitchProfileRequest{Profile: profileName})
	if err != nil {
		return fmt.Errorf("switch profile: %v", err)
	}
	if !resp.Success {
		return fmt.Errorf("switch profile: %s", resp.Error)
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
