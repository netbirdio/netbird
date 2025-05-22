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
	"fyne.io/systray"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// showProfilesUI creates and displays the Profiles window with a list of existing profiles,
// a button to add new profiles, allows removal, and lets the user switch the active profile.
func (s *serviceClient) showProfilesUI() {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return
	}

	profiles, err := s.mProfiles.getProfiles(s.ctx, conn)
	if err != nil {
		log.Errorf("get profiles: %v", err)
		return
	}

	var idx int
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
			if profile.Selected {
				indicator.SetText("✓")
			} else {
				indicator.SetText("")
			}
			nameLabel.SetText(profile.Name)

			// Configure Select/Active button
			selectBtn.SetText(func() string {
				if profile.Selected {
					return "Active"
				}
				return "Select"
			}())
			selectBtn.OnTapped = func() {
				if profile.Selected {
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
						// backend switch
						//err := s.switchProfile(profile.name)
						var err error
						if idx%2 == 0 {
							err = errors.New("failed to switch profile")
						} else {
							if idx%2 == 1 {
								dialog.ShowInformation(
									"Profile Switched",
									fmt.Sprintf("Profile '%s' switched successfully", profile.Name),
									s.wProfiles,
								)
							}
						}
						idx++
						if err != nil {
							dialog.ShowError(fmt.Errorf("failed to select profile: %w", err), s.wProfiles)
							return
						}
						// update slice flags

						//refresh()
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
						// backend remove
						//s.removeProfile(profile.name)
						// update slice and refresh
						//profiles = append(profiles[:i], profiles[i+1:]...)
						//refresh()
					},
					s.wProfiles,
				)
			}
		},
	)

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
				// backend create
				//s.createProfile(name)
				// add to slice, default unselected
				//profiles = append(profiles, profile{name: name, selected: false})
				//refresh()
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

func (s *serviceClient) updateProfiles() {
	conn, err := s.getSrvClient(defaultFailTimeout)
	if err != nil {
		log.Errorf("get client: %v", err)
		return
	}

	s.mProfiles.updateProfiles(s.ctx, conn)
}

type profileMenu struct {
	mtx      sync.Mutex
	menu     *systray.MenuItem
	profiles []*proto.Profile
}

type profile struct {
	name     string
	selected bool
}

func newProfileMenu(menu *systray.MenuItem) *profileMenu {
	p := &profileMenu{
		menu:     menu,
		profiles: make([]*proto.Profile, 0),
	}
	return p
}

func (p *profileMenu) loadProfiles(profiles []*proto.Profile) {

	// Clear existing profiles
	p.clearProfiles()

	p.mtx.Lock()
	defer p.mtx.Unlock()
	// Add new profiles
	p.profiles = append(p.profiles, profiles...)
}

func (p *profileMenu) clearProfiles() {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.profiles = make([]*proto.Profile, 0)
}

func (p *profileMenu) updateProfiles(ctx context.Context, conn proto.DaemonServiceClient) {
	profiles, err := p.getProfiles(ctx, conn)
	if err != nil {
		log.Errorf("get profiles: %v", err)
		return
	}

	p.loadProfiles(profiles)

}

func (p *profileMenu) getProfiles(pCtx context.Context, conn proto.DaemonServiceClient) ([]*proto.Profile, error) {
	ctx, cancel := context.WithTimeout(pCtx, defaultFailTimeout)
	defer cancel()

	resp, err := conn.GetProfiles(ctx, &proto.GetProfilesRequest{})
	if err != nil {
		return nil, fmt.Errorf("get profiles: %v", err)
	}

	return resp.Profiles, nil
}
