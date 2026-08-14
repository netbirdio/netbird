GO ?= go

LIBEXECDIR ?= /usr/libexec
DBUS_SYSTEM_D ?= /etc/dbus-1/system.d
UDEV_RULES_D ?= /usr/lib/udev/rules.d
VPNSERVICEDIR ?= $(shell pkg-config --variable=vpnservicedir libnm 2>/dev/null)

# libnm.pc does not export a "plugindir" variable; the real plugin directory
# is libdir/NetworkManager (e.g. /usr/lib64/NetworkManager on Fedora).
PLUGINDIR ?= $(shell pkg-config --variable=plugindir libnm 2>/dev/null)
ifeq ($(PLUGINDIR),)
PLUGINDIR := $(shell pkg-config --variable=libdir libnm 2>/dev/null)/NetworkManager
endif

GOFILES := $(shell find . -name '*.go')

.PHONY: all properties install uninstall clean

all: bin/nm-netbird-service bin/nm-netbird-auth-dialog properties

bin/nm-netbird-service: $(GOFILES)
	@mkdir -p bin
	$(GO) build -o $@ ./cmd/nm-netbird-service

bin/nm-netbird-auth-dialog: $(GOFILES)
	@mkdir -p bin
	$(GO) build -o $@ ./cmd/nm-netbird-auth-dialog

ifeq ($(SKIP_PROPERTIES),1)
properties:
	@echo "skipping client/networkmanager/properties (SKIP_PROPERTIES=1)"
else
properties:
	$(MAKE) -C properties
endif

install: all
	install -d $(DESTDIR)$(LIBEXECDIR)
	install -m 0755 bin/nm-netbird-service $(DESTDIR)$(LIBEXECDIR)/nm-netbird-service
	install -m 0755 bin/nm-netbird-auth-dialog $(DESTDIR)$(LIBEXECDIR)/nm-netbird-auth-dialog
	install -d $(DESTDIR)$(DBUS_SYSTEM_D)
	install -m 0644 nm-netbird-service.conf $(DESTDIR)$(DBUS_SYSTEM_D)/nm-netbird-service.conf
	install -d $(DESTDIR)$(UDEV_RULES_D)
	install -m 0644 udev/71-nm-unmanaged-netbird.rules $(DESTDIR)$(UDEV_RULES_D)/71-nm-unmanaged-netbird.rules
	-udevadm control --reload-rules 2>/dev/null
	@test -n "$(VPNSERVICEDIR)" || { \
		echo "error: could not determine libnm's VPN service directory (pkg-config --variable=vpnservicedir libnm)." >&2; \
		echo "pass it explicitly: make install VPNSERVICEDIR=/path/to/NetworkManager/VPN" >&2; \
		exit 1; \
	}
	install -d $(DESTDIR)$(VPNSERVICEDIR)
	sed -e 's|@LIBEXECDIR@|$(LIBEXECDIR)|g' -e 's|@PLUGINDIR@|$(PLUGINDIR)|g' \
		nm-netbird-service.name.in > $(DESTDIR)$(VPNSERVICEDIR)/nm-netbird-service.name
ifneq ($(SKIP_PROPERTIES),1)
	$(MAKE) -C properties install
endif
	@if command -v getenforce >/dev/null 2>&1 && [ "$$(getenforce)" = "Enforcing" ]; then \
		echo; \
		echo "SELinux is enforcing on this system: also run 'make -C selinux install'"; \
		echo "(see README.md) or nm-netbird-service will fail to reach the netbird daemon."; \
	fi

# Undoes everything install did, including the udev rule that hides
# netbird's tunnel interface from NetworkManager -- that behavior should
# only apply while this plugin is actually installed, not linger after.
uninstall:
	rm -f $(DESTDIR)$(LIBEXECDIR)/nm-netbird-service
	rm -f $(DESTDIR)$(LIBEXECDIR)/nm-netbird-auth-dialog
	rm -f $(DESTDIR)$(DBUS_SYSTEM_D)/nm-netbird-service.conf
	rm -f $(DESTDIR)$(UDEV_RULES_D)/71-nm-unmanaged-netbird.rules
	-udevadm control --reload-rules 2>/dev/null
	rm -f $(DESTDIR)$(VPNSERVICEDIR)/nm-netbird-service.name
ifneq ($(SKIP_PROPERTIES),1)
	$(MAKE) -C properties uninstall
endif
	@echo "note: the SELinux module (if installed) is separate: sudo semodule -r nm_netbird_local"

clean:
	rm -rf bin
	$(MAKE) -C properties clean
