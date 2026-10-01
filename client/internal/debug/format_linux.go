//go:build linux && !android

package debug

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

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
