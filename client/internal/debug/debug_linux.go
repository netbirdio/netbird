//go:build linux && !android

package debug

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// addIPRules collects and adds IP rules to the archive
func (g *BundleGenerator) addIPRules() error {
	log.Info("Collecting IP rules")
	ipRules, err := systemops.GetIPRules()
	if err != nil {
		return fmt.Errorf("get IP rules: %w", err)
	}

	rulesContent := formatIPRulesTable(ipRules, g.anonymize, g.anonymizer)
	rulesReader := strings.NewReader(rulesContent)
	if err := g.addFileToZip(rulesReader, "ip_rules.txt"); err != nil {
		return fmt.Errorf("add IP rules file to zip: %w", err)
	}

	return nil
}

const (
	maxLogEntries = 100000
	maxLogAge     = 7 * 24 * time.Hour // Last 7 days
)

// trySystemdLogFallback attempts to get logs from systemd journal as fallback
func (g *BundleGenerator) trySystemdLogFallback() error {
	log.Debug("Attempting to collect systemd journal logs")

	serviceName := getServiceName()
	journalLogs, err := getSystemdLogs(serviceName)
	if err != nil {
		return fmt.Errorf("get systemd logs for %s: %w", serviceName, err)
	}

	if strings.Contains(journalLogs, "No recent log entries found") {
		log.Debug("No recent log entries found in systemd journal")
		return nil
	}

	if g.anonymize {
		journalLogs = g.anonymizer.AnonymizeString(journalLogs)
	}

	logReader := strings.NewReader(journalLogs)
	fileName := fmt.Sprintf("systemd-%s.log", serviceName)
	if err := g.addFileToZip(logReader, fileName); err != nil {
		return fmt.Errorf("add systemd logs to bundle: %w", err)
	}

	log.Infof("Added systemd journal logs for %s to debug bundle", serviceName)
	return nil
}

// getServiceName gets the service name from environment or defaults to netbird
func getServiceName() string {
	if unitName := os.Getenv("SYSTEMD_UNIT"); unitName != "" {
		log.Debugf("Detected SYSTEMD_UNIT environment variable: %s", unitName)
		return unitName
	}

	return "netbird"
}

// getSystemdLogs retrieves logs from systemd journal for a specific service using journalctl
func getSystemdLogs(serviceName string) (string, error) {
	args := []string{
		"-u", fmt.Sprintf("%s.service", serviceName),
		"--since", fmt.Sprintf("-%s", maxLogAge.String()),
		"--lines", fmt.Sprintf("%d", maxLogEntries),
		"--no-pager",
		"--output", "short-iso",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("journalctl command timed out after 30 seconds")
		}
		if strings.Contains(err.Error(), "executable file not found") {
			return "", fmt.Errorf("journalctl command not found: %w", err)
		}
		return "", fmt.Errorf("execute journalctl: %w (stderr: %s)", err, stderr.String())
	}

	logs := stdout.String()
	if strings.TrimSpace(logs) == "" {
		return "No recent log entries found in systemd journal", nil
	}

	header := fmt.Sprintf("=== Systemd Journal Logs for %s.service (last %d entries, max %s) ===\n",
		serviceName, maxLogEntries, maxLogAge.String())

	return header + logs, nil
}

// addFirewallRules collects and adds firewall rules to the archive
func (g *BundleGenerator) addFirewallRules() error {
	log.Info("Collecting firewall rules")
	iptablesRules, err := collectIPTablesRules()
	if err != nil {
		log.Warnf("Failed to collect iptables rules: %v", err)
	} else {
		if g.anonymize {
			iptablesRules = g.anonymizer.AnonymizeString(iptablesRules)
		}
		if err := g.addFileToZip(strings.NewReader(iptablesRules), "iptables.txt"); err != nil {
			log.Warnf("Failed to add iptables rules to bundle: %v", err)
		}
	}

	nftablesRules, err := collectNFTablesRules()
	if err != nil {
		log.Warnf("Failed to collect nftables rules: %v", err)
	} else {
		if g.anonymize {
			nftablesRules = g.anonymizer.AnonymizeString(nftablesRules)
		}
		if err := g.addFileToZip(strings.NewReader(nftablesRules), "nftables.txt"); err != nil {
			log.Warnf("Failed to add nftables rules to bundle: %v", err)
		}
	}

	return nil
}

// collectIPTablesRules collects rules using both iptables-save and verbose listing
func collectIPTablesRules() (string, error) {
	var builder strings.Builder

	saveOutput, err := collectIPTablesSave()
	if err != nil {
		log.Warnf("Failed to collect iptables rules using iptables-save: %v", err)
	} else {
		builder.WriteString("=== iptables-save output ===\n")
		builder.WriteString(saveOutput)
		builder.WriteString("\n")
	}

	ipsetOutput, err := collectIPSets()
	if err != nil {
		log.Warnf("Failed to collect ipset information: %v", err)
	} else {
		builder.WriteString("=== ipset list output ===\n")
		builder.WriteString(ipsetOutput)
		builder.WriteString("\n")
	}

	builder.WriteString("=== iptables -v -n -L output ===\n")

	tables := []string{"filter", "nat", "mangle", "raw", "security"}

	for _, table := range tables {
		builder.WriteString(fmt.Sprintf("*%s\n", table))

		stats, err := getTableStatistics(table)
		if err != nil {
			log.Warnf("Failed to get statistics for table %s: %v", table, err)
			continue
		}
		builder.WriteString(stats)
		builder.WriteString("\n")
	}

	return builder.String(), nil
}

// collectIPSets collects information about ipsets
func collectIPSets() (string, error) {
	cmd := exec.Command("ipset", "list")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			return "", fmt.Errorf("ipset command not found: %w", err)
		}
		return "", fmt.Errorf("execute ipset list: %w (stderr: %s)", err, stderr.String())
	}

	ipsets := stdout.String()
	if strings.TrimSpace(ipsets) == "" {
		return "No ipsets found", nil
	}

	return ipsets, nil
}

// collectIPTablesSave uses iptables-save to get rule definitions
func collectIPTablesSave() (string, error) {
	cmd := exec.Command("iptables-save")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("execute iptables-save: %w (stderr: %s)", err, stderr.String())
	}

	rules := stdout.String()
	if strings.TrimSpace(rules) == "" {
		return "", fmt.Errorf("no iptables rules found")
	}

	return rules, nil
}

// getTableStatistics gets verbose statistics for an entire table using iptables command
func getTableStatistics(table string) (string, error) {
	cmd := exec.Command("iptables", "-v", "-n", "-L", "-t", table)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("execute iptables -v -n -L: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.String(), nil
}

// collectNFTablesRules attempts to collect nftables rules using either nft command or netlink
func collectNFTablesRules() (string, error) {
	rules, err := collectNFTablesFromCommand()
	if err != nil {
		log.Debugf("Failed to collect nftables rules using nft command: %v, falling back to netlink", err)
		rules, err = collectNFTablesFromNetlink()
		if err != nil {
			return "", fmt.Errorf("collect nftables rules using both nft and netlink failed: %w", err)
		}
	}
	return rules, nil
}

// collectNFTablesFromCommand attempts to collect rules using nft command
func collectNFTablesFromCommand() (string, error) {
	cmd := exec.Command("nft", "-a", "list", "ruleset")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("execute nft list ruleset: %w (stderr: %s)", err, stderr.String())
	}

	rules := stdout.String()
	if strings.TrimSpace(rules) == "" {
		return "", fmt.Errorf("no nftables rules found")
	}

	return rules, nil
}

// collectNFTablesFromNetlink collects rules using netlink library
func collectNFTablesFromNetlink() (string, error) {
	conn, err := nftables.New()
	if err != nil {
		return "", fmt.Errorf("create nftables connection: %w", err)
	}

	tables, err := conn.ListTables()
	if err != nil {
		return "", fmt.Errorf("list tables: %w", err)
	}

	sortTables(tables)
	return formatTables(conn, tables), nil
}

func formatTables(conn *nftables.Conn, tables []*nftables.Table) string {
	var builder strings.Builder

	for _, table := range tables {
		builder.WriteString(fmt.Sprintf("table %s %s {\n", formatFamily(table.Family), table.Name))

		chains, err := getAndSortTableChains(conn, table)
		if err != nil {
			log.Warnf("Failed to list chains for table %s: %v", table.Name, err)
			continue
		}

		for _, chain := range chains {
			formatChain(conn, table, chain, &builder)
		}

		if sets, err := conn.GetSets(table); err != nil {
			log.Warnf("Failed to get sets for table %s: %v", table.Name, err)
		} else if len(sets) > 0 {
			builder.WriteString("\n")
			for _, set := range sets {
				builder.WriteString(formatSet(conn, set))
			}
		}

		builder.WriteString("}\n")
	}

	return builder.String()
}

func getAndSortTableChains(conn *nftables.Conn, table *nftables.Table) ([]*nftables.Chain, error) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, err
	}

	var tableChains []*nftables.Chain
	for _, chain := range chains {
		if chain.Table.Name == table.Name && chain.Table.Family == table.Family {
			tableChains = append(tableChains, chain)
		}
	}

	sort.Slice(tableChains, func(i, j int) bool {
		return tableChains[i].Name < tableChains[j].Name
	})

	return tableChains, nil
}

func formatChain(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, builder *strings.Builder) {
	builder.WriteString(fmt.Sprintf("\tchain %s {\n", chain.Name))

	if chain.Type != "" {
		var policy string
		if chain.Policy != nil {
			policy = fmt.Sprintf("; policy %s", formatPolicy(*chain.Policy))
		}
		builder.WriteString(fmt.Sprintf("\t\ttype %s hook %s priority %d%s\n",
			formatChainType(chain.Type),
			formatChainHook(chain.Hooknum),
			chain.Priority,
			policy))
	}

	rules, err := conn.GetRules(table, chain)
	if err != nil {
		log.Warnf("Failed to get rules for chain %s: %v", chain.Name, err)
	} else {
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Position < rules[j].Position
		})
		for _, rule := range rules {
			builder.WriteString(formatRule(rule))
		}
	}

	builder.WriteString("\t}\n")
}

func sortTables(tables []*nftables.Table) {
	sort.Slice(tables, func(i, j int) bool {
		if tables[i].Family != tables[j].Family {
			return tables[i].Family < tables[j].Family
		}
		return tables[i].Name < tables[j].Name
	})
}

func formatFamily(family nftables.TableFamily) string {
	switch family {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	default:
		return fmt.Sprintf("family-%d", family)
	}
}

func formatChainType(typ nftables.ChainType) string {
	switch typ {
	case nftables.ChainTypeFilter:
		return "filter"
	case nftables.ChainTypeNAT:
		return "nat"
	case nftables.ChainTypeRoute:
		return "route"
	default:
		return fmt.Sprintf("type-%s", typ)
	}
}

func formatChainHook(hook *nftables.ChainHook) string {
	if hook == nil {
		return "none"
	}
	switch *hook {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	default:
		return fmt.Sprintf("hook-%d", *hook)
	}
}

func formatPolicy(policy nftables.ChainPolicy) string {
	switch policy {
	case nftables.ChainPolicyDrop:
		return "drop"
	case nftables.ChainPolicyAccept:
		return "accept"
	default:
		return fmt.Sprintf("policy-%d", policy)
	}
}

func formatRule(rule *nftables.Rule) string {
	var builder strings.Builder
	builder.WriteString("\t\t")

	for i := 0; i < len(rule.Exprs); i++ {
		if i > 0 {
			builder.WriteString(" ")
		}
		i = formatExprSequence(&builder, rule.Exprs, i)
	}

	builder.WriteString("\n")
	return builder.String()
}

func formatExprSequence(builder *strings.Builder, exprs []expr.Any, i int) int {
	curr := exprs[i]

	if meta, ok := curr.(*expr.Meta); ok && i+1 < len(exprs) {
		if cmp, ok := exprs[i+1].(*expr.Cmp); ok {
			if formatted := formatMetaWithCmp(meta, cmp); formatted != "" {
				builder.WriteString(formatted)
				return i + 1
			}
		}
	}

	if payload, ok := curr.(*expr.Payload); ok && i+1 < len(exprs) {
		if cmp, ok := exprs[i+1].(*expr.Cmp); ok {
			builder.WriteString(formatPayloadWithCmp(payload, cmp))
			return i + 1
		}
	}

	builder.WriteString(formatExpr(curr))
	return i
}

func formatMetaWithCmp(meta *expr.Meta, cmp *expr.Cmp) string {
	switch meta.Key {
	case expr.MetaKeyIIFNAME:
		name := strings.TrimRight(string(cmp.Data), "\x00")
		return fmt.Sprintf("iifname %s %q", formatCmpOp(cmp.Op), name)
	case expr.MetaKeyOIFNAME:
		name := strings.TrimRight(string(cmp.Data), "\x00")
		return fmt.Sprintf("oifname %s %q", formatCmpOp(cmp.Op), name)
	case expr.MetaKeyMARK:
		if len(cmp.Data) == 4 {
			val := binary.BigEndian.Uint32(cmp.Data)
			return fmt.Sprintf("meta mark %s 0x%x", formatCmpOp(cmp.Op), val)
		}
	}
	return ""
}

func formatPayloadWithCmp(p *expr.Payload, cmp *expr.Cmp) string {
	if p.Base == expr.PayloadBaseNetworkHeader {
		switch p.Offset {
		case 12:
			switch p.Len {
			case 4, 2:
				return fmt.Sprintf("ip saddr %s %s", formatCmpOp(cmp.Op), formatIPBytes(cmp.Data))
			}
		case 16:
			switch p.Len {
			case 4, 2:
				return fmt.Sprintf("ip daddr %s %s", formatCmpOp(cmp.Op), formatIPBytes(cmp.Data))
			}
		}
	}
	return fmt.Sprintf("%d reg%d [%d:%d] %s %v",
		p.Base, p.DestRegister, p.Offset, p.Len,
		formatCmpOp(cmp.Op), cmp.Data)
}

func formatIPBytes(data []byte) string {
	if len(data) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
	} else if len(data) == 2 {
		return fmt.Sprintf("%d.%d.0.0/16", data[0], data[1])
	}
	return fmt.Sprintf("%v", data)
}

func formatCmpOp(op expr.CmpOp) string {
	switch op {
	case expr.CmpOpEq:
		return "=="
	case expr.CmpOpNeq:
		return "!="
	case expr.CmpOpLt:
		return "<"
	case expr.CmpOpLte:
		return "<="
	case expr.CmpOpGt:
		return ">"
	case expr.CmpOpGte:
		return ">="
	default:
		return fmt.Sprintf("op-%d", op)
	}
}

// formatExpr formats an expression in nft-like syntax
func formatExpr(exp expr.Any) string {
	switch e := exp.(type) {
	case *expr.Meta:
		return formatMeta(e)
	case *expr.Cmp:
		return formatCmp(e)
	case *expr.Payload:
		return formatPayload(e)
	case *expr.Verdict:
		return formatVerdict(e)
	case *expr.Counter:
		return fmt.Sprintf("counter packets %d bytes %d", e.Packets, e.Bytes)
	case *expr.Masq:
		return "masquerade"
	case *expr.NAT:
		return formatNat(e)
	case *expr.Match:
		return formatMatch(e)
	case *expr.Queue:
		return fmt.Sprintf("queue num %d", e.Num)
	case *expr.Lookup:
		return fmt.Sprintf("@%s", e.SetName)
	case *expr.Bitwise:
		return formatBitwise(e)
	case *expr.Fib:
		return formatFib(e)
	case *expr.Target:
		return fmt.Sprintf("jump %s", e.Name)
	case *expr.Immediate:
		if e.Register == 1 {
			return formatImmediateData(e.Data)
		}
		return fmt.Sprintf("immediate %v", e.Data)
	default:
		return fmt.Sprintf("<%T>", exp)
	}
}

func formatImmediateData(data []byte) string {
	if len(data) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
	}
	return fmt.Sprintf("%v", data)
}

func formatMeta(e *expr.Meta) string {
	if e.SourceRegister {
		return fmt.Sprintf("meta %s set reg %d", formatMetaKey(e.Key), e.Register)
	}

	switch e.Key {
	case expr.MetaKeyIIFNAME,
		expr.MetaKeyOIFNAME,
		expr.MetaKeyBRIIIFNAME,
		expr.MetaKeyBRIOIFNAME:
		return formatMetaKey(e.Key)

	case expr.MetaKeyMARK:
		return "mark"
	}

	return fmt.Sprintf("meta %s => reg %d", formatMetaKey(e.Key), e.Register)
}

func formatMetaKey(key expr.MetaKey) string {
	switch key {
	case expr.MetaKeyLEN:
		return "length"
	case expr.MetaKeyPROTOCOL:
		return "protocol"
	case expr.MetaKeyPRIORITY:
		return "priority"
	case expr.MetaKeyMARK:
		return "mark"
	case expr.MetaKeyIIF:
		return "iif"
	case expr.MetaKeyOIF:
		return "oif"
	case expr.MetaKeyIIFNAME:
		return "iifname"
	case expr.MetaKeyOIFNAME:
		return "oifname"
	case expr.MetaKeyIIFTYPE:
		return "iiftype"
	case expr.MetaKeyOIFTYPE:
		return "oiftype"
	case expr.MetaKeySKUID:
		return "skuid"
	case expr.MetaKeySKGID:
		return "skgid"
	case expr.MetaKeyNFTRACE:
		return "nftrace"
	case expr.MetaKeyRTCLASSID:
		return "rtclassid"
	case expr.MetaKeySECMARK:
		return "secmark"
	case expr.MetaKeyNFPROTO:
		return "nfproto"
	case expr.MetaKeyL4PROTO:
		return "l4proto"
	case expr.MetaKeyBRIIIFNAME:
		return "briifname"
	case expr.MetaKeyBRIOIFNAME:
		return "broifname"
	case expr.MetaKeyPKTTYPE:
		return "pkttype"
	case expr.MetaKeyCPU:
		return "cpu"
	case expr.MetaKeyIIFGROUP:
		return "iifgroup"
	case expr.MetaKeyOIFGROUP:
		return "oifgroup"
	case expr.MetaKeyCGROUP:
		return "cgroup"
	case expr.MetaKeyPRANDOM:
		return "prandom"
	default:
		return fmt.Sprintf("meta-%d", key)
	}
}

func formatCmp(e *expr.Cmp) string {
	ops := map[expr.CmpOp]string{
		expr.CmpOpEq:  "==",
		expr.CmpOpNeq: "!=",
		expr.CmpOpLt:  "<",
		expr.CmpOpLte: "<=",
		expr.CmpOpGt:  ">",
		expr.CmpOpGte: ">=",
	}
	return fmt.Sprintf("%s %v", ops[e.Op], e.Data)
}

func formatPayload(e *expr.Payload) string {
	var proto string
	switch e.Base {
	case expr.PayloadBaseNetworkHeader:
		proto = "ip"
	case expr.PayloadBaseTransportHeader:
		proto = "tcp"
	default:
		proto = fmt.Sprintf("payload-%d", e.Base)
	}
	return fmt.Sprintf("%s reg%d [%d:%d]", proto, e.DestRegister, e.Offset, e.Len)
}

func formatVerdict(e *expr.Verdict) string {
	switch e.Kind {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictJump:
		return fmt.Sprintf("jump %s", e.Chain)
	case expr.VerdictGoto:
		return fmt.Sprintf("goto %s", e.Chain)
	case expr.VerdictReturn:
		return "return"
	default:
		return fmt.Sprintf("verdict-%d", e.Kind)
	}
}

func formatNat(e *expr.NAT) string {
	switch e.Type {
	case expr.NATTypeSourceNAT:
		return "snat"
	case expr.NATTypeDestNAT:
		return "dnat"
	default:
		return fmt.Sprintf("nat-%d", e.Type)
	}
}

func formatMatch(e *expr.Match) string {
	return fmt.Sprintf("match %s rev %d", e.Name, e.Rev)
}

func formatBitwise(e *expr.Bitwise) string {
	return fmt.Sprintf("bitwise reg%d = reg%d & %v ^ %v",
		e.DestRegister, e.SourceRegister, e.Mask, e.Xor)
}

func formatFib(e *expr.Fib) string {
	var flags []string
	if e.FlagSADDR {
		flags = append(flags, "saddr")
	}
	if e.FlagDADDR {
		flags = append(flags, "daddr")
	}
	if e.FlagMARK {
		flags = append(flags, "mark")
	}
	if e.FlagIIF {
		flags = append(flags, "iif")
	}
	if e.FlagOIF {
		flags = append(flags, "oif")
	}
	if e.ResultADDRTYPE {
		flags = append(flags, "type")
	}
	return fmt.Sprintf("fib reg%d %s", e.Register, strings.Join(flags, ","))
}

func formatSet(conn *nftables.Conn, set *nftables.Set) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("\tset %s {\n", set.Name))
	builder.WriteString(fmt.Sprintf("\t\ttype %s\n", formatSetKeyType(set.KeyType)))
	if set.ID > 0 {
		builder.WriteString(fmt.Sprintf("\t\t# handle %d\n", set.ID))
	}

	elements, err := conn.GetSetElements(set)
	if err != nil {
		log.Warnf("Failed to get elements for set %s: %v", set.Name, err)
	} else if len(elements) > 0 {
		builder.WriteString("\t\telements = {")
		for i, elem := range elements {
			if i > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString(fmt.Sprintf("%v", elem.Key))
		}
		builder.WriteString("}\n")
	}

	builder.WriteString("\t}\n")
	return builder.String()
}

func formatSetKeyType(keyType nftables.SetDatatype) string {
	switch keyType {
	case nftables.TypeInvalid:
		return "invalid"
	case nftables.TypeIPAddr:
		return "ipv4_addr"
	case nftables.TypeIP6Addr:
		return "ipv6_addr"
	case nftables.TypeEtherAddr:
		return "ether_addr"
	case nftables.TypeInetProto:
		return "inet_proto"
	case nftables.TypeInetService:
		return "inet_service"
	case nftables.TypeMark:
		return "mark"
	default:
		return fmt.Sprintf("type-%v", keyType)
	}
}
