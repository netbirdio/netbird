//go:build android

package android

import (
	"fmt"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/route"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

func toggleRoute(id string, manager routemanager.Manager,
	operationName string,
	routeOperation func(routes []route.NetID, allRoutes []route.NetID) error) error {
	netID := route.NetID(id)
	routes := []route.NetID{netID}

	log.Debugf("%s with id: %s", operationName, id)

	if err := routeOperation(routes, maps.Keys(manager.GetClientRoutesWithNetID())); err != nil {
		log.Debugf("error when %s: %s", operationName, err)
		return fmt.Errorf("error %s: %w", operationName, err)
	}

	manager.TriggerSelection(manager.GetClientRoutes())

	return nil
}

type routeCommand interface {
	toggleRoute() error
}

type selectRouteCommand struct {
	route   string
	manager routemanager.Manager
}

func (s selectRouteCommand) toggleRoute() error {
	routeSelector := s.manager.GetRouteSelector()
	if routeSelector == nil {
		return fmt.Errorf("no route selector available")
	}

	routeOperation := func(routes []route.NetID, allRoutes []route.NetID) error {
		return routeSelector.SelectRoutes(routes, true, allRoutes)
	}

	return toggleRoute(s.route, s.manager, "selecting route", routeOperation)
}

type deselectRouteCommand struct {
	route   string
	manager routemanager.Manager
}

func (d deselectRouteCommand) toggleRoute() error {
	routeSelector := d.manager.GetRouteSelector()
	if routeSelector == nil {
		return fmt.Errorf("no route selector available")
	}

	return toggleRoute(d.route, d.manager, "deselecting route", routeSelector.DeselectRoutes)
}
