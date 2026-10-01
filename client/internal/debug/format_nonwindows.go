//go:build !windows

package debug

import (
	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// buildPlatformSpecificRouteTable builds headers and rows for non-Windows platforms
func buildPlatformSpecificRouteTable(detailedRoutes []systemops.DetailedRoute, anonymize bool, anonymizer *anonymize.Anonymizer) ([]string, [][]string) {
	headers := []string{"Destination", "Gateway", "Interface", "Idx", "Metric", "Protocol", "Scope", "Type", "Table", "Flags"}

	var rows [][]string
	for _, route := range detailedRoutes {
		destStr := formatRouteDestination(route.Route.Dst, anonymize, anonymizer)
		gatewayStr := formatRouteGateway(route.Route.Gw, anonymize, anonymizer)
		interfaceStr := formatRouteInterface(route.Route.Interface)
		indexStr := formatInterfaceIndex(route.InterfaceIndex)
		metricStr := formatRouteMetric(route.Metric)

		row := []string{destStr, gatewayStr, interfaceStr, indexStr, metricStr, route.Protocol, route.Scope, route.Type, route.Table, route.Flags}
		rows = append(rows, row)
	}

	return headers, rows
}
