//go:build !android && !ios && !freebsd && !js

package main

import (
	"errors"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/ui/instancecolor"
	"github.com/netbirdio/netbird/client/ui/services"
)

// instanceColour is the named installation's colour, nil for the default
// installation or when the record holds no valid colour.
var instanceColour *color.NRGBA

// useInstance makes the UI process run as the installation given with
// --instance and returns it with the label and colour of its record. The record
// is untrusted input: an invalid label falls back to the canonical name and an
// invalid colour to no colour.
func useInstance(input string) (instance.Instance, error) {
	inst, err := instance.For(input)
	if err != nil {
		if errors.Is(err, instance.ErrNamedUnsupported) {
			return instance.Instance{}, err
		}
		return instance.Instance{}, fmt.Errorf("invalid installation name: %w", err)
	}
	if inst.IsDefault() {
		return inst, nil
	}

	inst = inst.WithLabel(string(inst.Name()))
	rec, err := instance.LoadRecord(inst.Name())
	switch {
	case err == nil:
		var roleErr error
		if inst, roleErr = rec.Apply(inst); roleErr != nil {
			log.Warnf("installation record of %s: %v", inst.Name(), roleErr)
		}
		if c, cerr := instancecolor.Parse(rec.Color); cerr == nil {
			instanceColour = &c
		} else {
			log.Warnf("installation record of %s: %v; showing no colour", inst.Name(), cerr)
		}
	case !errors.Is(err, instance.ErrNoRecord):
		log.Warnf("read installation record of %s: %v", inst.Name(), err)
	}

	instance.SetCurrent(inst)
	return inst, nil
}

// installationDetails is what the settings window and the window header show
// about the installation. The default installation shows nothing.
func installationDetails(inst instance.Instance) services.InstallationDetails {
	if inst.IsDefault() {
		return services.InstallationDetails{}
	}
	d := services.InstallationDetails{
		Named: true,
		Name:  string(inst.Name()),
		Label: inst.Label(),
		Role:  string(inst.Role()),
	}
	if instanceColour != nil {
		d.Color = instancecolor.Hex(*instanceColour)
	}
	return d
}

// notificationLogoFile is where a named UI keeps the dotted logo it shows on
// its notifications, rewritten at every start.
const notificationLogoFile = "notification-logo.png"

// writeNotificationLogo draws the installation colour on the window logo for
// the notifications and returns the file it wrote, or "" for an installation
// without colour or when writing fails: notifications then show the plain logo.
func writeNotificationLogo(inst instance.Instance) string {
	if instanceColour == nil {
		return ""
	}
	logo, err := instancecolor.NotificationLogo(iconWindow, *instanceColour, instancecolor.RingOnDark)
	if err != nil {
		log.Warnf("draw the notification logo: %v", err)
		return ""
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		log.Warnf("locate the per-user directory for the notification logo: %v", err)
		return ""
	}
	dir = filepath.Join(dir, inst.UserDirName())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Warnf("create %s: %v", dir, err)
		return ""
	}
	path := filepath.Join(dir, notificationLogoFile)
	if err := os.WriteFile(path, logo, 0o600); err != nil {
		log.Warnf("write the notification logo: %v", err)
		return ""
	}
	return path
}

// webviewUserDataPath gives a named UI its own WebView2 data folder: two
// WebView2 instances cannot share one with different settings. The default UI
// keeps the library default.
func webviewUserDataPath(inst instance.Instance) string {
	name := inst.WebviewDataDirName()
	if name == "" {
		return ""
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		log.Warnf("locate the per-user directory for WebView2 data: %v", err)
		return ""
	}
	return filepath.Join(dir, inst.UserDirName(), name)
}

// trayTooltip is the hover text of the tray icon. The default installation
// keeps the translated brand name; a named one shows its label.
func trayTooltip(loc *Localizer) string {
	if inst := instance.Current(); !inst.IsDefault() {
		return inst.DisplayName()
	}
	return loc.T("tray.tooltip")
}

// colouredIcons caches the composited tray icons, keyed by source icon and
// ring, so a state change does not decode and re-encode a PNG.
var colouredIcons sync.Map

// colourIcon draws the installation colour on a tray icon. Without a colour,
// as for the default installation, the icon bytes are returned unchanged.
func colourIcon(icon []byte, ring color.NRGBA) []byte {
	if instanceColour == nil || len(icon) == 0 {
		return icon
	}
	key := fmt.Sprintf("%p/%v", &icon[0], ring)
	if v, ok := colouredIcons.Load(key); ok {
		return v.([]byte)
	}
	out, err := instancecolor.Overlay(icon, *instanceColour, ring)
	if err != nil {
		log.Warnf("draw the installation colour on the tray icon: %v", err)
		return icon
	}
	colouredIcons.Store(key, out)
	return out
}
