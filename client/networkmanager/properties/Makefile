PKG_CONFIG ?= pkg-config
CC ?= gcc
REQUIRED_PKGS := libnm gmodule-2.0 gtk4 gtk+-3.0

CORE_NAME := libnm-vpn-plugin-netbird.so
EDITOR_GTK4_NAME := libnm-gtk4-vpn-plugin-netbird-editor.so
EDITOR_GTK3_NAME := libnm-vpn-plugin-netbird-editor.so

# libnm.pc does not export a "plugindir" variable; the real plugin directory
# is libdir/NetworkManager (e.g. /usr/lib64/NetworkManager on Fedora).
PLUGINDIR ?= $(shell $(PKG_CONFIG) --variable=plugindir libnm 2>/dev/null)
ifeq ($(PLUGINDIR),)
PLUGINDIR := $(shell $(PKG_CONFIG) --variable=libdir libnm 2>/dev/null)/NetworkManager
endif

LIBNM_CFLAGS := $(shell $(PKG_CONFIG) --cflags libnm 2>/dev/null)
LIBNM_LIBS := $(shell $(PKG_CONFIG) --libs libnm 2>/dev/null)
GMODULE_CFLAGS := $(shell $(PKG_CONFIG) --cflags gmodule-2.0 2>/dev/null)
GMODULE_LIBS := $(shell $(PKG_CONFIG) --libs gmodule-2.0 2>/dev/null)
GTK4_CFLAGS := $(shell $(PKG_CONFIG) --cflags gtk4 2>/dev/null)
GTK4_LIBS := $(shell $(PKG_CONFIG) --libs gtk4 2>/dev/null)
GTK3_CFLAGS := $(shell $(PKG_CONFIG) --cflags gtk+-3.0 2>/dev/null)
GTK3_LIBS := $(shell $(PKG_CONFIG) --libs gtk+-3.0 2>/dev/null)

CFLAGS += -fPIC -Wall -DPLUGINDIR='"$(PLUGINDIR)"'

.PHONY: all check-deps install uninstall clean

all: check-deps $(CORE_NAME) $(EDITOR_GTK4_NAME) $(EDITOR_GTK3_NAME)

check-deps:
	@$(PKG_CONFIG) --exists $(REQUIRED_PKGS) || { \
		echo "error: missing build dependencies for the NetBird NetworkManager editor plugin ($(REQUIRED_PKGS))." >&2; \
		echo "install them first, e.g. on Fedora:" >&2; \
		echo "  sudo dnf install NetworkManager-libnm-devel glib2-devel gtk4-devel gtk3-devel" >&2; \
		echo "or on Debian/Ubuntu:" >&2; \
		echo "  sudo apt install libnm-dev libglib2.0-dev libgtk-4-dev libgtk-3-dev" >&2; \
		exit 1; \
	}
	@test -n "$(PLUGINDIR)" || { \
		echo "error: could not determine libnm's plugin directory (libdir/NetworkManager)." >&2; \
		echo "pass it explicitly: make PLUGINDIR=/path/to/NetworkManager" >&2; \
		exit 1; \
	}

# Core plugin: toolkit-independent on purpose. NetworkManager and GNOME
# Shell's own secret-agent both load this .so directly (not just
# nm-connection-editor), so it must not link GTK -- doing so previously broke
# GNOME Shell's SecretsRequired handling by loading a second GTK stack
# inside its Wayland compositor process. It picks and dlopen's whichever of
# the two editor .so's below matches the GTK toolkit already loaded in the
# host process (nm-connection-editor is still GTK3 on some distributions
# even where GTK4 is the default elsewhere; GNOME Settings' network panel is
# GTK4), matching how NetworkManager's own bundled plugins do this.
nm-netbird-editor-plugin.o: nm-netbird-editor-plugin.c
	$(CC) $(CFLAGS) $(LIBNM_CFLAGS) $(GMODULE_CFLAGS) -c -o $@ $<

$(CORE_NAME): nm-netbird-editor-plugin.o
	$(CC) -shared -o $@ $^ $(LIBNM_LIBS) $(GMODULE_LIBS)

resources.c: gresource.xml nm-netbird-dialog.ui
	glib-compile-resources --generate-source --target=$@ --sourcedir=. gresource.xml

nm-netbird-editor.o: nm-netbird-editor.c
	$(CC) $(CFLAGS) $(LIBNM_CFLAGS) $(GTK4_CFLAGS) -c -o $@ $<

resources.o: resources.c
	$(CC) $(CFLAGS) $(GTK4_CFLAGS) -c -o $@ $<

$(EDITOR_GTK4_NAME): nm-netbird-editor.o resources.o
	$(CC) -shared -o $@ $^ $(LIBNM_LIBS) $(GTK4_LIBS)

resources-gtk3.c: gresource-gtk3.xml nm-netbird-dialog-gtk3.ui
	glib-compile-resources --generate-source --target=$@ --sourcedir=. gresource-gtk3.xml

nm-netbird-editor-gtk3.o: nm-netbird-editor-gtk3.c
	$(CC) $(CFLAGS) $(LIBNM_CFLAGS) $(GTK3_CFLAGS) -c -o $@ $<

resources-gtk3.o: resources-gtk3.c
	$(CC) $(CFLAGS) $(GTK3_CFLAGS) -c -o $@ $<

$(EDITOR_GTK3_NAME): nm-netbird-editor-gtk3.o resources-gtk3.o
	$(CC) -shared -o $@ $^ $(LIBNM_LIBS) $(GTK3_LIBS)

install: all
	install -d $(DESTDIR)$(PLUGINDIR)
	install -m 0644 $(CORE_NAME) $(DESTDIR)$(PLUGINDIR)/$(CORE_NAME)
	install -m 0644 $(EDITOR_GTK4_NAME) $(DESTDIR)$(PLUGINDIR)/$(EDITOR_GTK4_NAME)
	install -m 0644 $(EDITOR_GTK3_NAME) $(DESTDIR)$(PLUGINDIR)/$(EDITOR_GTK3_NAME)

uninstall:
	rm -f $(DESTDIR)$(PLUGINDIR)/$(CORE_NAME)
	rm -f $(DESTDIR)$(PLUGINDIR)/$(EDITOR_GTK4_NAME)
	rm -f $(DESTDIR)$(PLUGINDIR)/$(EDITOR_GTK3_NAME)

clean:
	rm -f nm-netbird-editor-plugin.o nm-netbird-editor.o nm-netbird-editor-gtk3.o \
		resources.o resources-gtk3.o \
		$(CORE_NAME) $(EDITOR_GTK4_NAME) $(EDITOR_GTK3_NAME) \
		resources.c resources-gtk3.c
