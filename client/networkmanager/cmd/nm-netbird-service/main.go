//go:build linux

// Command nm-netbird-service is the NetworkManager VPN service plugin
// NetworkManager spawns per active "netbird" connection. It implements
// org.freedesktop.NetworkManager.VPN.Plugin and drives the real netbird
// daemon's gRPC API to connect and disconnect.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/networkmanager/vpnplugin"
)

func main() {
	busName := flag.String("bus-name", "", "D-Bus name to claim for this VPN plugin instance")
	debug := flag.Bool("debug", false, "enable debug logging")
	persist := flag.Bool("persist", false, "keep running after Disconnect instead of exiting")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	if err := run(*busName, *persist); err != nil {
		log.Fatal(err)
	}
}

func run(busName string, persist bool) error {
	if busName == "" {
		return fmt.Errorf("missing required --bus-name")
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("connect system bus: %w", err)
	}
	defer conn.Close()

	reply, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("request bus name %s: %w", busName, err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("bus name %s is already owned", busName)
	}

	plugin := vpnplugin.New(conn, persist)
	if err := plugin.Export(); err != nil {
		return fmt.Errorf("export VPN plugin object: %w", err)
	}

	waitForShutdown(plugin)
	return nil
}

func waitForShutdown(plugin *vpnplugin.Plugin) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	select {
	case s := <-sig:
		log.Debugf("received signal %v, disconnecting", s)
		if err := plugin.Disconnect(); err != nil {
			log.Warnf("disconnect: %v", err)
		}
		// Exit on signal regardless of --persist: the process is being
		// killed either way, persist only governs voluntary exit after a
		// D-Bus-initiated Disconnect.
		select {
		case <-plugin.Quit():
		case <-time.After(15 * time.Second):
			log.Warn("timed out waiting for netbird down during shutdown")
		}
	case <-plugin.Quit():
	}
}
