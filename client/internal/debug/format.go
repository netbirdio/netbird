package debug

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/management/domain"
)

func formatInterfaces(interfaces []net.Interface, anonymize bool, anonymizer *anonymize.Anonymizer) string {
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Name < interfaces[j].Name
	})

	var builder strings.Builder
	builder.WriteString("Network Interfaces:\n")

	for _, iface := range interfaces {
		builder.WriteString(fmt.Sprintf("\nInterface: %s\n", iface.Name))
		builder.WriteString(fmt.Sprintf("  Index: %d\n", iface.Index))
		builder.WriteString(fmt.Sprintf("  MTU: %d\n", iface.MTU))
		builder.WriteString(fmt.Sprintf("  Flags: %v\n", iface.Flags))

		addrs, err := iface.Addrs()
		if err != nil {
			builder.WriteString(fmt.Sprintf("  Addresses: Error retrieving addresses: %v\n", err))
		} else {
			builder.WriteString("  Addresses:\n")
			for _, addr := range addrs {
				prefix, err := netip.ParsePrefix(addr.String())
				if err != nil {
					builder.WriteString(fmt.Sprintf("    Error parsing address: %v\n", err))
					continue
				}
				ip := prefix.Addr()
				if anonymize {
					ip = anonymizer.AnonymizeIP(ip)
				}
				builder.WriteString(fmt.Sprintf("    %s/%d\n", ip, prefix.Bits()))
			}
		}
	}

	return builder.String()
}

func formatResolvedDomains(resolvedDomains map[domain.Domain]peer.ResolvedDomainInfo, anonymize bool, anonymizer *anonymize.Anonymizer) string {
	if len(resolvedDomains) == 0 {
		return "No resolved domains found.\n"
	}

	var builder strings.Builder
	builder.WriteString("Resolved Domains:\n")
	builder.WriteString("=================\n\n")

	var sortedParents []domain.Domain
	for parentDomain := range resolvedDomains {
		sortedParents = append(sortedParents, parentDomain)
	}
	sort.Slice(sortedParents, func(i, j int) bool {
		return sortedParents[i].SafeString() < sortedParents[j].SafeString()
	})

	for _, parentDomain := range sortedParents {
		info := resolvedDomains[parentDomain]

		parentKey := parentDomain.SafeString()
		if anonymize {
			parentKey = anonymizer.AnonymizeDomain(parentKey)
		}

		builder.WriteString(fmt.Sprintf("%s:\n", parentKey))

		var sortedIPs []string
		for _, prefix := range info.Prefixes {
			ipStr := prefix.String()
			if anonymize {
				anonymizedIP := anonymizer.AnonymizeIP(prefix.Addr())
				ipStr = fmt.Sprintf("%s/%d", anonymizedIP, prefix.Bits())
			}
			sortedIPs = append(sortedIPs, ipStr)
		}
		sort.Strings(sortedIPs)

		for _, ipStr := range sortedIPs {
			builder.WriteString(fmt.Sprintf("  %s\n", ipStr))
		}
		builder.WriteString("\n")
	}

	return builder.String()
}

func formatRoutesTable(detailedRoutes []systemops.DetailedRoute, anonymize bool, anonymizer *anonymize.Anonymizer) string {
	if len(detailedRoutes) == 0 {
		return "No routes found.\n"
	}

	sort.Slice(detailedRoutes, func(i, j int) bool {
		if detailedRoutes[i].Table != detailedRoutes[j].Table {
			return detailedRoutes[i].Table < detailedRoutes[j].Table
		}
		return detailedRoutes[i].Route.Dst.String() < detailedRoutes[j].Route.Dst.String()
	})

	headers, rows := buildPlatformSpecificRouteTable(detailedRoutes, anonymize, anonymizer)

	return formatTable("Routing Table:", headers, rows)
}

func formatRouteDestination(destination netip.Prefix, anonymize bool, anonymizer *anonymize.Anonymizer) string {
	if anonymize {
		anonymizedDestIP := anonymizer.AnonymizeIP(destination.Addr())
		return fmt.Sprintf("%s/%d", anonymizedDestIP, destination.Bits())
	}
	return destination.String()
}

func formatRouteGateway(gateway netip.Addr, anonymize bool, anonymizer *anonymize.Anonymizer) string {
	if gateway.IsValid() {
		if anonymize {
			return anonymizer.AnonymizeIP(gateway).String()
		}
		return gateway.String()
	}
	return "-"
}

func formatRouteInterface(iface *net.Interface) string {
	if iface != nil {
		return iface.Name
	}
	return "-"
}

func formatInterfaceIndex(index int) string {
	if index <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", index)
}

func formatRouteMetric(metric int) string {
	if metric < 0 {
		return "-"
	}
	return fmt.Sprintf("%d", metric)
}

func formatTable(title string, headers []string, rows [][]string) string {
	widths := make([]int, len(headers))

	for i, header := range headers {
		widths[i] = len(header)
	}

	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	for i := range widths {
		widths[i] += 2
	}

	var formatParts []string
	for _, width := range widths {
		formatParts = append(formatParts, fmt.Sprintf("%%-%ds", width))
	}
	formatStr := strings.Join(formatParts, "") + "\n"

	var builder strings.Builder
	builder.WriteString(title + "\n")
	builder.WriteString(strings.Repeat("=", len(title)) + "\n\n")

	headerArgs := make([]interface{}, len(headers))
	for i, header := range headers {
		headerArgs[i] = header
	}
	builder.WriteString(fmt.Sprintf(formatStr, headerArgs...))

	separatorArgs := make([]interface{}, len(headers))
	for i, width := range widths {
		separatorArgs[i] = strings.Repeat("-", width-2)
	}
	builder.WriteString(fmt.Sprintf(formatStr, separatorArgs...))

	for _, row := range rows {
		rowArgs := make([]interface{}, len(row))
		for i, cell := range row {
			rowArgs[i] = cell
		}
		builder.WriteString(fmt.Sprintf(formatStr, rowArgs...))
	}

	return builder.String()
}
