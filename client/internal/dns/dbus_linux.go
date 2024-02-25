//go:build !android

package dns

import (
	"context"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

const dbusDefaultFlag = 0

func isDbusListenerRunning(dest string, path dbus.ObjectPath) bool {
	obj, closeConn, err := getDbusObject(dest, path)
	if err != nil {
		log.Tracef("error getting dbus object: %s", err)
		return false
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	if err = obj.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0).Store(); err != nil {
		log.Tracef("error calling dbus: %s", err)
		return false
	}

	return true
}

func getDbusObject(dest string, path dbus.ObjectPath) (dbus.BusObject, func(), error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, nil, fmt.Errorf("get dbus: %w", err)
	}
	obj := conn.Object(dest, path)

	closeFunc := func() {
		closeErr := conn.Close()
		if closeErr != nil {
			log.Warnf("got an error closing dbus connection, err: %s", closeErr)
		}
	}

	return obj, closeFunc, nil
}
