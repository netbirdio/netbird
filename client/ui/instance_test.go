//go:build !android && !ios && !freebsd && !js

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/ui/instancecolor"
	"github.com/netbirdio/netbird/client/ui/services"
)

// SBS-COL-02: the default installation's tray icons stay byte-identical.
func TestColourIconDefaultUnchanged(t *testing.T) {
	require.Nil(t, instanceColour, "the default installation has no colour")
	for _, icon := range [][]byte{iconConnected, iconConnectedDark, iconError, iconUpdateDisconnected} {
		assert.Equal(t, icon, colourIcon(icon, instancecolor.RingOnLight), "icon bytes")
	}
}

func TestColourIconNamed(t *testing.T) {
	c, err := instancecolor.Parse("skyblue")
	require.NoError(t, err)
	instanceColour = &c
	t.Cleanup(func() { instanceColour = nil })

	out := colourIcon(iconConnected, instancecolor.RingOnLight)
	assert.NotEqual(t, iconConnected, out, "dot drawn")
	again := colourIcon(iconConnected, instancecolor.RingOnLight)
	assert.Same(t, &out[0], &again[0], "composited once and cached")
	dark := colourIcon(iconConnected, instancecolor.RingOnDark)
	assert.NotEqual(t, out, dark, "the ring follows the taskbar theme")
}

// SBS-UI-09: the settings window shows nothing for the default installation.
func TestInstallationDetailsDefault(t *testing.T) {
	assert.Equal(t, services.InstallationDetails{}, installationDetails(instance.Default()), "default installation")
}

func TestInstallationDetailsNamed(t *testing.T) {
	inst, err := instance.ForPlatform("windows", "acme")
	require.NoError(t, err)
	inst = inst.WithLabel("ACME").WithRole(instance.RolePrimary)

	assert.Equal(t, services.InstallationDetails{Named: true, Name: "acme", Label: "ACME", Role: "primary"},
		installationDetails(inst), "named, no colour")

	c, err := instancecolor.Parse("skyblue")
	require.NoError(t, err)
	instanceColour = &c
	t.Cleanup(func() { instanceColour = nil })
	assert.Equal(t, "#56B4E9", installationDetails(inst).Color, "colour")
}

// SBS-COL-04: a named installation's notifications carry its dotted logo.
func TestNotifierAddsLogo(t *testing.T) {
	plain := notifications.NotificationOptions{ID: "x", Title: "t"}
	assert.Equal(t, plain, (&Notifier{}).withLogo(plain), "no logo: unchanged")

	n := &Notifier{logo: `C:\logo.png`}
	got := n.withLogo(plain)
	assert.Equal(t, []notifications.NotificationAttachment{{Path: `C:\logo.png`, Type: logoAttachmentType}},
		got.Attachments, "logo added")
	assert.Empty(t, plain.Attachments, "the caller's options are not changed")

	own := notifications.NotificationOptions{Attachments: []notifications.NotificationAttachment{
		{Path: "own.png", Type: logoAttachmentType},
	}}
	assert.Equal(t, own, n.withLogo(own), "a notification's own logo wins")
}

func TestWriteNotificationLogo(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	inst, err := instance.ForPlatform("windows", "acme")
	require.NoError(t, err)

	assert.Empty(t, writeNotificationLogo(inst), "no colour, no logo")

	c, err := instancecolor.Parse("orange")
	require.NoError(t, err)
	instanceColour = &c
	t.Cleanup(func() { instanceColour = nil })

	path := writeNotificationLogo(inst)
	require.NotEmpty(t, path, "logo written")
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	want, err := instancecolor.NotificationLogo(iconWindow, c, instancecolor.RingOnDark)
	require.NoError(t, err)
	assert.Equal(t, want, b, "the dotted window logo")
	assert.Equal(t, inst.UserDirName(), filepath.Base(filepath.Dir(path)), "in the installation's own folder")
}
