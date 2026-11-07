//go:build linux && cgo && !android && !ios

package services

/*
// The GTK major version is the only difference between the two Linux builds, so
// it is selected by these two directives rather than by keeping a second copy of
// this file per version: the C below and the Go wrappers under it are identical
// for GTK3 and GTK4, and both resolve <gtk/gtk.h> through pkg-config.
#cgo gtk3 pkg-config: gtk+-3.0
#cgo !gtk3 pkg-config: gtk4
#include <stdlib.h>
#include <gtk/gtk.h>

static char *nbGetGtkThemeName(void) {
	GtkSettings *settings = gtk_settings_get_default();
	if (settings == NULL) {
		return NULL;
	}
	char *name = NULL;
	g_object_get(settings, "gtk-theme-name", &name, NULL);
	return name;
}

// name may be NULL to keep the current theme name.
//
// On GTK 4.20+ writing gtk-application-prefer-dark-theme reloads the theme
// without re-registering its gresource, so themes like Yaru lose their CSS.
// Only write the flag when it changes, and clear the theme name around the
// write so the real theme is loaded fresh afterwards.
static void nbSetGtkTheme(const char *name, int dark) {
	GtkSettings *settings = gtk_settings_get_default();
	if (settings == NULL) {
		return;
	}

	gboolean want = dark ? TRUE : FALSE;
	gboolean current = FALSE;
	g_object_get(settings, "gtk-application-prefer-dark-theme", &current, NULL);
	gboolean flagChanged = (current ? TRUE : FALSE) != want;

	char *currentName = NULL;
	g_object_get(settings, "gtk-theme-name", &currentName, NULL);
	const char *target = (name != NULL && name[0] != '\0') ? name : currentName;
	gboolean haveTarget = target != NULL && target[0] != '\0';
	gboolean nameChanged = haveTarget && g_strcmp0(target, currentName) != 0;

	if (haveTarget && (flagChanged || nameChanged)) {
		g_object_set(settings, "gtk-theme-name", "", NULL);
	}
	if (flagChanged) {
		g_object_set(settings, "gtk-application-prefer-dark-theme", want, NULL);
	}
	if (haveTarget && (flagChanged || nameChanged)) {
		g_object_set(settings, "gtk-theme-name", target, NULL);
	}
	g_free(currentName);
}

static void nbFreeGtkString(char *s) { g_free(s); }
*/
import "C"

import "unsafe"

func gtkThemeName() string {
	c := C.nbGetGtkThemeName()
	if c == nil {
		return ""
	}
	defer C.nbFreeGtkString(c)
	return C.GoString(c)
}

func applyGtkTheme(name string, dark bool) {
	var cName *C.char
	if name != "" {
		cName = C.CString(name)
		defer C.free(unsafe.Pointer(cName))
	}
	var forced C.int
	if dark {
		forced = 1
	}
	C.nbSetGtkTheme(cName, forced)
}
