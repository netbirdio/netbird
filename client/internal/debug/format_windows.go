//go:build windows

package debug

import (
	"fmt"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// buildPlatformSpecificRouteTable builds headers and rows for Windows with interface metrics
func buildPlatformSpecificRouteTable(detailedRoutes []systemops.DetailedRoute, anonymize bool, anonymizer *anonymize.Anonymizer) ([]string, [][]string) {
	headers := []string{"Destination", "Gateway", "Interface", "Idx", "Metric", "If Metric", "Protocol", "Age", "Origin"}

	var rows [][]string
	for _, route := range detailedRoutes {
		destStr := formatRouteDestination(route.Route.Dst, anonymize, anonymizer)
		gatewayStr := formatRouteGateway(route.Route.Gw, anonymize, anonymizer)
		interfaceStr := formatRouteInterface(route.Route.Interface)
		indexStr := formatInterfaceIndex(route.InterfaceIndex)
		metricStr := formatRouteMetric(route.Metric)
		ifMetricStr := formatInterfaceMetric(route.InterfaceMetric)

		row := []string{destStr, gatewayStr, interfaceStr, indexStr, metricStr, ifMetricStr, route.Protocol, route.Scope, route.Type}
		rows = append(rows, row)
	}

	return headers, rows
}

func formatInterfaceMetric(metric int) string {
	if metric < 0 {
		return "-"
	}
	return fmt.Sprintf("%d", metric)
}
