//go:build !windows && !android && !ios && !freebsd && !js

package main

import "github.com/netbirdio/netbird/client/internal/instance"

// prepareToastIdentity is a no-op: named installations exist only on Windows.
func prepareToastIdentity(instance.Instance) {}

// labelToastSource is a no-op: named installations exist only on Windows.
func labelToastSource(instance.Instance) {}
