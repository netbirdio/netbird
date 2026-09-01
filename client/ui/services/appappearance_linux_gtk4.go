//go:build linux && cgo && !gtk3 && !android && !ios

package services

/*
#cgo pkg-config: gtk4
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

// name may be NULL to leave the theme name untouched.
static void nbSetGtkTheme(const char *name, int dark) {
	GtkSettings *settings = gtk_settings_get_default();
	if (settings == NULL) {
		return;
	}
	if (name != NULL && name[0] != '\0') {
		g_object_set(settings, "gtk-theme-name", name, NULL);
	}
	g_object_set(settings, "gtk-application-prefer-dark-theme", dark ? TRUE : FALSE, NULL);
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
