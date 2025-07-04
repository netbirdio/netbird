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

func formatIPRulesTable(ipRules []systemops.IPRule, anonymize bool, anonymizer *anonymize.Anonymizer) string {
	if len(ipRules) == 0 {
		return "No IP rules found.\n"
	}

	sort.Slice(ipRules, func(i, j int) bool {
		return ipRules[i].Priority < ipRules[j].Priority
	})

	columnConfig := detectIPRuleColumns(ipRules)

	headers := buildIPRuleHeaders(columnConfig)

	rows := buildIPRuleRows(ipRules, columnConfig, anonymize, anonymizer)

	return formatTable("IP Rules:", headers, rows)
}

type ipRuleColumnConfig struct {
	hasInvert, hasTo, hasMark, hasIIF, hasOIF, hasSuppressPlen bool
}

func detectIPRuleColumns(ipRules []systemops.IPRule) ipRuleColumnConfig {
	var config ipRuleColumnConfig
	for _, rule := range ipRules {
		if rule.Invert {
			config.hasInvert = true
		}
		if rule.To.IsValid() {
			config.hasTo = true
		}
		if rule.Mark != 0 {
			config.hasMark = true
		}
		if rule.IIF != "" {
			config.hasIIF = true
		}
		if rule.OIF != "" {
			config.hasOIF = true
		}
		if rule.SuppressPlen >= 0 {
			config.hasSuppressPlen = true
		}
	}
	return config
}

func buildIPRuleHeaders(config ipRuleColumnConfig) []string {
	var headers []string

	headers = append(headers, "Priority")
	if config.hasInvert {
		headers = append(headers, "Not")
	}
	headers = append(headers, "From")
	if config.hasTo {
		headers = append(headers, "To")
	}
	if config.hasMark {
		headers = append(headers, "FWMark")
	}
	if config.hasIIF {
		headers = append(headers, "IIF")
	}
	if config.hasOIF {
		headers = append(headers, "OIF")
	}
	headers = append(headers, "Table")
	headers = append(headers, "Action")
	if config.hasSuppressPlen {
		headers = append(headers, "SuppressPlen")
	}

	return headers
}

func buildIPRuleRows(ipRules []systemops.IPRule, config ipRuleColumnConfig, anonymize bool, anonymizer *anonymize.Anonymizer) [][]string {
	var rows [][]string
	for _, rule := range ipRules {
		row := buildSingleIPRuleRow(rule, config, anonymize, anonymizer)
		rows = append(rows, row)
	}
	return rows
}

func buildSingleIPRuleRow(rule systemops.IPRule, config ipRuleColumnConfig, anonymize bool, anonymizer *anonymize.Anonymizer) []string {
	var row []string

	row = append(row, fmt.Sprintf("%d", rule.Priority))

	if config.hasInvert {
		row = append(row, formatIPRuleInvert(rule.Invert))
	}

	row = append(row, formatIPRuleAddress(rule.From, "all", anonymize, anonymizer))

	if config.hasTo {
		row = append(row, formatIPRuleAddress(rule.To, "-", anonymize, anonymizer))
	}

	if config.hasMark {
		row = append(row, formatIPRuleMark(rule.Mark, rule.Mask))
	}

	if config.hasIIF {
		row = append(row, formatIPRuleInterface(rule.IIF))
	}

	if config.hasOIF {
		row = append(row, formatIPRuleInterface(rule.OIF))
	}

	row = append(row, rule.Table)

	row = append(row, formatIPRuleAction(rule.Action))

	if config.hasSuppressPlen {
		row = append(row, formatIPRuleSuppressPlen(rule.SuppressPlen))
	}

	return row
}

func formatIPRuleInvert(invert bool) string {
	if invert {
		return "not"
	}
	return "-"
}

func formatIPRuleAction(action string) string {
	if action == "unspec" {
		return "lookup"
	}
	return action
}

func formatIPRuleSuppressPlen(suppressPlen int) string {
	if suppressPlen >= 0 {
		return fmt.Sprintf("%d", suppressPlen)
	}
	return "-"
}

func formatIPRuleAddress(prefix netip.Prefix, defaultVal string, anonymize bool, anonymizer *anonymize.Anonymizer) string {
	if !prefix.IsValid() {
		return defaultVal
	}

	if anonymize {
		anonymizedIP := anonymizer.AnonymizeIP(prefix.Addr())
		return fmt.Sprintf("%s/%d", anonymizedIP, prefix.Bits())
	}
	return prefix.String()
}

func formatIPRuleMark(mark, mask uint32) string {
	if mark == 0 {
		return "-"
	}
	if mask != 0 {
		return fmt.Sprintf("0x%x/0x%x", mark, mask)
	}
	return fmt.Sprintf("0x%x", mark)
}

func formatIPRuleInterface(iface string) string {
	if iface == "" {
		return "-"
	}
	return iface
}
