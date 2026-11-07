//go:build windows

package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// appUserModelIDKey holds a toast identity; the Wails fork reads its
// CustomActivator value at start-up and generates one when it is missing.
const appUserModelIDKey = `Software\Classes\AppUserModelId\`

// prepareToastIdentity gives a named UI its own toast activator before Wails
// reads it. Every UI start points the activator's COM server at its own
// executable, so with a shared activator the last UI started would receive
// every toast click, and "Extend now" could extend another installation's
// session. The default UI keeps what the MSI or the library set up.
func prepareToastIdentity(inst instance.Instance) {
	clsid := inst.ToastActivatorCLSID()
	if clsid == "" {
		return
	}
	if err := setToastValue(inst.UIAppName(), "CustomActivator", clsid); err != nil {
		log.Warnf("register the toast activator of %s: %v", inst.Name(), err)
	}
}

// labelToastSource shows "NetBird (ACME)" as a named UI's notification source.
// The toast library writes the AppUserModelID as display name at start-up, so
// this runs after that.
func labelToastSource(inst instance.Instance) {
	if inst.IsDefault() {
		return
	}
	if err := setToastValue(inst.UIAppName(), "DisplayName", inst.DisplayName()); err != nil {
		log.Warnf("set the notification source name of %s: %v", inst.Name(), err)
	}
}

func setToastValue(appID, name, value string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, appUserModelIDKey+appID, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s%s: %w", appUserModelIDKey, appID, err)
	}
	defer func() { _ = k.Close() }()
	return k.SetStringValue(name, value)
}
