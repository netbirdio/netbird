//go:build !ios

package dnsinterceptor

import log "github.com/sirupsen/logrus"

func waitForRouteSettlement(_ *log.Entry) {}
