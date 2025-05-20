package main

import "fyne.io/systray"

type profileMenu struct {
	menu       *systray.MenuItem
	profiles   []profileMenuItem
	manageItem *systray.MenuItem
}

type profileMenuItem struct {
	menuItem *systray.MenuItem
}

type profile struct {
	name     string
	selected bool
}

func newProfileMenu(menu *systray.MenuItem) *profileMenu {
	p := &profileMenu{
		menu: menu,
	}
	return p
}

func (p *profileMenu) loadProfiles() {

	// Load profiles from the configuration
	//profiles := config.GetProfiles()
	profiles := []profile{
		{name: "Default", selected: true},
		{name: "Profile 1", selected: false},
		{name: "Profile 2", selected: false},
	}

	// Clear existing profiles
	p.clearProfiles()

	for _, profile := range profiles {
		p.addProfile(profile)
	}

	// add manage profiles item
	p.menu.AddSeparator()
	p.manageItem = p.menu.AddSubMenuItem("Manage Profiles", "Manage your profiles")

}

func (p *profileMenu) addProfile(profile profile) {
	profName := profile.name
	if profile.selected {
		profName += " *"
	}

	menuItem := p.menu.AddSubMenuItem(profName, "Switch to "+profile.name)
	p.profiles = append(p.profiles, profileMenuItem{menuItem: menuItem})

}
func (p *profileMenu) clearProfiles() {
	// Remove all existing profile menu items
	for _, item := range p.profiles {
		item.menuItem.Remove()
	}
	p.profiles = nil
}
