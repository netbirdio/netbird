package differs

import (
	"fmt"
	"reflect"
	"slices"

	nbroute "github.com/netbirdio/netbird/route"
	"github.com/r3labs/diff"
)

type RouteComparator struct{}

func NewRouteComparator() *RouteComparator {
	return &RouteComparator{}
}

func (d *RouteComparator) Match(a, b reflect.Value) bool {
	return diff.AreType(a, b, reflect.TypeOf(&nbroute.Route{})) ||
		diff.AreType(a, b, reflect.TypeOf([]*nbroute.Route{}))
}

func (d *RouteComparator) Diff(cl *diff.Changelog, path []string, a, b reflect.Value) error {
	if err := handleInvalidKind(cl, path, a, b); err != nil {
		return err
	}

	if a.Kind() == reflect.Slice && b.Kind() == reflect.Slice {
		return handleSliceKind(d, cl, path, a, b)
	}

	route1, ok1 := a.Interface().(*nbroute.Route)
	route2, ok2 := b.Interface().(*nbroute.Route)
	if !ok1 || !ok2 {
		return fmt.Errorf("invalid type for Route")
	}

	if route1.ID != route2.ID {
		cl.Add(diff.UPDATE, append(path, "ID"), route1.ID, route2.ID)
	}
	if route1.AccountID != route2.AccountID {
		cl.Add(diff.UPDATE, append(path, "AccountID"), route1.AccountID, route2.AccountID)
	}
	if route1.Network.String() != route2.Network.String() {
		cl.Add(diff.UPDATE, append(path, "Network"), route1.Network.String(), route2.Network.String())
	}
	if !slices.Equal(route1.Domains, route2.Domains) {
		cl.Add(diff.UPDATE, append(path, "Domains"), route1.Domains, route2.Domains)
	}
	if route1.KeepRoute != route2.KeepRoute {
		cl.Add(diff.UPDATE, append(path, "KeepRoute"), route1.KeepRoute, route2.KeepRoute)
	}
	if route1.NetID != route2.NetID {
		cl.Add(diff.UPDATE, append(path, "NetID"), route1.NetID, route2.NetID)
	}
	if route1.Description != route2.Description {
		cl.Add(diff.UPDATE, append(path, "Description"), route1.Description, route2.Description)
	}
	if route1.Peer != route2.Peer {
		cl.Add(diff.UPDATE, append(path, "Peer"), route1.Peer, route2.Peer)
	}
	if !slices.Equal(route1.PeerGroups, route2.PeerGroups) {
		cl.Add(diff.UPDATE, append(path, "PeerGroups"), route1.PeerGroups, route2.PeerGroups)
	}
	if route1.NetworkType != route2.NetworkType {
		cl.Add(diff.UPDATE, append(path, "NetworkType"), route1.NetworkType, route2.NetworkType)
	}
	if route1.Masquerade != route2.Masquerade {
		cl.Add(diff.UPDATE, append(path, "Masquerade"), route1.Masquerade, route2.Masquerade)
	}
	if route1.Metric != route2.Metric {
		cl.Add(diff.UPDATE, append(path, "Metric"), route1.Metric, route2.Metric)
	}
	if route1.Enabled != route2.Enabled {
		cl.Add(diff.UPDATE, append(path, "Enabled"), route1.Enabled, route2.Enabled)
	}
	if !slices.Equal(route1.Groups, route2.Groups) {
		cl.Add(diff.UPDATE, append(path, "Groups"), route1.Groups, route2.Groups)
	}

	return nil
}
