//go:build windows

package debug

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
)

const dnsInfoFileName = "dns_windows.txt"

const (
	gpoDNSClientRoot = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
	tcpipParamsPath  = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	dnscacheParams   = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`
)

// interfaceDNSValues are the per-interface values that decide how a name is
// resolved and registered. Everything the DNS host manager writes is in here,
// so a bundle shows both what we set and what it replaced.
var interfaceDNSValues = []string{
	"NameServer",
	"DhcpNameServer",
	"Domain",
	"DhcpDomain",
	"SearchList",
	"RegistrationEnabled",
	"DisableDynamicUpdate",
	"MaxNumberOfAddressesToRegister",
	"EnableDHCP",
}

// addDNSInfo collects and adds DNS configuration information to the archive
func (g *BundleGenerator) addDNSInfo() error {
	if err := g.addFileToZip(strings.NewReader(g.collectDNSInfo()), dnsInfoFileName); err != nil {
		return fmt.Errorf("add DNS info to zip: %w", err)
	}

	return nil
}

// collectDNSInfo renders the report. Everything below it reaches the platform
// through COM and through lazily resolved procedures, which panic when a
// procedure is missing rather than returning an error, and a debug bundle is not
// allowed to take the daemon down. The panic is contained here, and whatever was
// collected before it is kept and reported with it.
func (g *BundleGenerator) collectDNSInfo() (content string) {
	var sb strings.Builder

	defer func() {
		if r := recover(); r != nil {
			log.Errorf("collecting Windows DNS configuration panicked: %v", r)
			fmt.Fprintf(&sb, "\nerror: collection stopped: %v\n", r)
		}
		content = sb.String()
	}()

	sb.WriteString("Windows DNS configuration\n")
	sb.WriteString("=========================\n")

	adapters, adaptersErr := adapterAddresses()

	g.writeNRPTRules(&sb, "NRPT rules, local policy store", nbdns.DNSPolicyConfigRoot)
	g.writeNRPTRules(&sb, "NRPT rules, group policy store", nbdns.GPODNSPolicyConfigRoot)
	g.writeEffectiveNRPTPolicies(&sb)
	g.writeRegistryKey(&sb, "DNS client group policy", gpoDNSClientRoot)
	g.writeRegistryKey(&sb, "Global TCP/IP parameters", tcpipParamsPath)
	g.writeRegistryKey(&sb, "Dnscache parameters", dnscacheParams)
	g.writeInterfaceDNS(&sb, "Per-interface DNS, IPv4", nbdns.InterfaceConfigPath, adapterNames(adapters))
	g.writeInterfaceDNS(&sb, "Per-interface DNS, IPv6", nbdns.InterfaceConfigPathV6, adapterNames(adapters))
	g.writeAdapterDNS(&sb, adapters, adaptersErr)

	return sb.String()
}

// writeNRPTRules lists every rule in a policy store, ours and any other
// product's, since a foreign rule for the same namespace decides resolution
// just as ours does. Rules the client wrote are marked.
func (g *BundleGenerator) writeNRPTRules(sb *strings.Builder, title, root string) {
	writeSection(sb, title, root)

	names, err := subKeyNames(root)
	if err != nil {
		fmt.Fprintf(sb, "error: %v\n", err)
		return
	}

	if len(names) == 0 {
		sb.WriteString("no rules\n")
		return
	}

	for _, name := range names {
		owner := ""
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(nbdns.NRPTKeyPrefix)) {
			owner = "  (netbird)"
		}
		fmt.Fprintf(sb, "%s%s\n", name, owner)
		g.writeValues(sb, root+`\`+name, nil, "  ")
	}
}

// writeEffectiveNRPTPolicies reports the table the resolver answers from, which
// the registry cannot show: a rule is written before it is loaded, and it keeps
// being enforced after its key is gone until the resolver reloads its policy.
func (g *BundleGenerator) writeEffectiveNRPTPolicies(sb *strings.Builder) {
	writeSection(sb, "NRPT policy table in effect", nrptPolicyClass+"."+nrptPolicyMethod+" in "+nrptPolicyNamespace)

	entries, err := effectiveNRPTPolicies()
	if err != nil {
		fmt.Fprintf(sb, "error: %v\n", err)
		return
	}

	if len(entries) == 0 {
		sb.WriteString("no policies\n")
		return
	}

	for _, entry := range entries {
		fmt.Fprintf(sb, "%s\n", g.anonymizeValue("Namespace", entry.namespace))
		for _, value := range entry.values {
			fmt.Fprintf(sb, "  %s: %s\n", value.name, g.anonymizeValue(value.name, value.value))
		}
	}
}

// writeInterfaceDNS reports the DNS values of every interface that has any, so
// the netbird interface can be compared against the physical ones. The registry
// keys the values by GUID, so each is named from the adapter list; a GUID with
// no adapter is a leftover key of an interface that no longer exists.
func (g *BundleGenerator) writeInterfaceDNS(sb *strings.Builder, title, root string, names map[string]string) {
	writeSection(sb, title, root)

	guids, err := subKeyNames(root)
	if err != nil {
		fmt.Fprintf(sb, "error: %v\n", err)
		return
	}

	var reported int
	for _, guid := range guids {
		var iface strings.Builder
		g.writeValues(&iface, root+`\`+guid, interfaceDNSValues, "  ")
		if iface.Len() == 0 {
			continue
		}

		name, ok := names[strings.ToLower(guid)]
		if !ok {
			name = "no adapter with this GUID"
		}

		reported++
		fmt.Fprintf(sb, "%s (%s)\n%s", guid, name, iface.String())
	}

	if reported == 0 {
		sb.WriteString("no interface holds DNS values\n")
	}
}

// writeRegistryKey reports the values of a single key, without its subkeys.
func (g *BundleGenerator) writeRegistryKey(sb *strings.Builder, title, path string) {
	writeSection(sb, title, path)

	var values strings.Builder
	g.writeValues(&values, path, nil, "")
	if values.Len() == 0 {
		sb.WriteString("no values\n")
		return
	}

	sb.WriteString(values.String())
}

// writeValues renders the values of a key. A nil names list reports every
// value, otherwise only those named and present.
func (g *BundleGenerator) writeValues(sb *strings.Builder, path string, names []string, indent string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	switch {
	case errors.Is(err, registry.ErrNotExist), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		// an absent key is the normal state for the GPO store and for
		// interfaces without DNS settings
		log.Debugf("HKEY_LOCAL_MACHINE\\%s does not exist", path)
		return
	case err != nil:
		fmt.Fprintf(sb, "%serror: open HKEY_LOCAL_MACHINE\\%s: %v\n", indent, path, err)
		return
	}
	defer closeKey(k)

	if names == nil {
		names, err = k.ReadValueNames(-1)
		if err != nil {
			fmt.Fprintf(sb, "%serror: read value names: %v\n", indent, err)
			return
		}
	}

	for _, name := range names {
		value, err := readRegistryValue(k, name)
		switch {
		case errors.Is(err, registry.ErrNotExist):
			// the caller asks for a fixed set of values, most of which a
			// given interface does not carry
			continue
		case err != nil:
			// report rather than omit: a value that is there but cannot be
			// read reads as unset otherwise
			fmt.Fprintf(sb, "%s%s: error: %v\n", indent, name, err)
			continue
		}

		fmt.Fprintf(sb, "%s%s: %s\n", indent, name, g.anonymizeValue(name, value))
	}
}

// anonymizeValue redacts a registry value according to what its name says it
// holds. Domains and addresses are handled per entry rather than by the string
// pass: the pass only replaces domains something else in the bundle already
// seeded, and its address regex would eat the digit labels of a reverse zone.
func (g *BundleGenerator) anonymizeValue(name, value string) string {
	if !g.anonymize || value == "" {
		return value
	}

	switch {
	case holdsDomains(name):
		return joinValueEntries(splitValueEntries(value), g.anonymizeDomain)
	case holdsAddresses(name):
		return joinValueEntries(splitValueEntries(value), g.anonymizer.AnonymizeIPString)
	default:
		return g.anonymizer.AnonymizeString(value)
	}
}

// holdsDomains reports whether a value name holds domains: the domain list of
// an NRPT rule (Name) or of the policy table (Namespace), a search list, the
// DNS suffix values of the TCP/IP and policy keys, which all end in "Domain"
// (Domain, DhcpDomain, NV Domain, ICSDomain), and a proxy host name.
func holdsDomains(name string) bool {
	lower := strings.ToLower(name)
	return lower == "name" || lower == "namespace" || lower == "searchlist" ||
		strings.HasSuffix(lower, "domain") || strings.HasSuffix(lower, "proxyname")
}

// holdsAddresses reports whether a value name holds DNS server addresses
// (NameServer, DhcpNameServer, GenericDNSServers, NameServers).
func holdsAddresses(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "nameserver") || strings.Contains(lower, "dnsserver")
}

// adapterNames maps adapter GUIDs, as the registry keys the interfaces, to the
// names an operator sees.
func adapterNames(adapters []*windows.IpAdapterAddresses) map[string]string {
	names := make(map[string]string, len(adapters))
	for _, adapter := range adapters {
		guid := windows.BytePtrToString(adapter.AdapterName)
		names[strings.ToLower(guid)] = windows.UTF16PtrToString(adapter.FriendlyName)
	}
	return names
}

// writeAdapterDNS reports the resolver configuration in effect per adapter,
// which is what the resolver uses for a name no NRPT rule matches.
func (g *BundleGenerator) writeAdapterDNS(sb *strings.Builder, adapters []*windows.IpAdapterAddresses, err error) {
	writeSection(sb, "Adapter DNS configuration", "GetAdaptersAddresses")

	if err != nil {
		fmt.Fprintf(sb, "error: %v\n", err)
		return
	}

	for _, adapter := range adapters {
		name := windows.UTF16PtrToString(adapter.FriendlyName)
		suffix := g.anonymizeDomain(windows.UTF16PtrToString(adapter.DnsSuffix))

		fmt.Fprintf(sb, "%s (index %d, oper status %d)\n", name, adapter.IfIndex, adapter.OperStatus)
		fmt.Fprintf(sb, "  DNS suffix: %s\n", suffix)

		var servers []string
		for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
			addr, ok := netip.AddrFromSlice(server.Address.IP())
			if !ok {
				continue
			}

			addr = addr.Unmap()
			if g.anonymize {
				addr = g.anonymizer.AnonymizeIP(addr)
			}
			servers = append(servers, addr.String())
		}

		fmt.Fprintf(sb, "  DNS servers: %s\n", strings.Join(servers, ", "))
	}
}

// anonymizeDomain anonymizes a single domain, keeping the leading dot an NRPT
// match domain carries.
func (g *BundleGenerator) anonymizeDomain(entry string) string {
	if !g.anonymize {
		return entry
	}

	domain, dot := strings.CutPrefix(entry, ".")
	if domain == "" {
		return entry
	}

	anonymized := g.anonymizer.AnonymizeDomain(domain)
	if dot {
		anonymized = "." + anonymized
	}
	return anonymized
}

// splitValueEntries splits a registry value that holds a list. The separator
// differs per value: a REG_MULTI_SZ arrives joined with ", ", a SearchList is
// comma separated and a NameServer may use commas or spaces.
func splitValueEntries(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	})
}

func joinValueEntries(entries []string, anonymize func(string) string) string {
	for i, entry := range entries {
		entries[i] = anonymize(entry)
	}
	return strings.Join(entries, ", ")
}

func writeSection(sb *strings.Builder, title, source string) {
	fmt.Fprintf(sb, "\n%s\n%s\n%s\n", title, strings.Repeat("-", len(title)), source)
}

func subKeyNames(root string) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("open HKEY_LOCAL_MACHINE\\%s: %w", root, err)
	}
	defer closeKey(k)

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("read subkey names: %w", err)
	}

	return names, nil
}

// readRegistryValue renders a value as text regardless of its type, so an
// unexpected type in a policy key still shows up instead of being dropped.
func readRegistryValue(k registry.Key, name string) (string, error) {
	_, valueType, err := k.GetValue(name, nil)
	if err != nil {
		return "", fmt.Errorf("get value %s: %w", name, err)
	}

	switch valueType {
	case registry.SZ, registry.EXPAND_SZ:
		value, _, err := k.GetStringValue(name)
		if err != nil {
			return "", fmt.Errorf("get string value %s: %w", name, err)
		}
		return value, nil
	case registry.MULTI_SZ:
		values, _, err := k.GetStringsValue(name)
		if err != nil {
			return "", fmt.Errorf("get strings value %s: %w", name, err)
		}
		return strings.Join(values, ", "), nil
	case registry.DWORD, registry.QWORD:
		value, _, err := k.GetIntegerValue(name)
		if err != nil {
			return "", fmt.Errorf("get integer value %s: %w", name, err)
		}
		return fmt.Sprintf("%d (0x%x)", value, value), nil
	case registry.BINARY:
		value, _, err := k.GetBinaryValue(name)
		if err != nil {
			return "", fmt.Errorf("get binary value %s: %w", name, err)
		}
		return hex.EncodeToString(value), nil
	default:
		return fmt.Sprintf("<unhandled registry type %d>", valueType), nil
	}
}

// adapterAddresses returns the adapter list including DNS servers. The call
// reports the size it needs, so grow the buffer and retry until it fits.
func adapterAddresses() (adapters []*windows.IpAdapterAddresses, err error) {
	// GetAdaptersAddresses is resolved on first use and panics when it is
	// missing, so this reports it as an error and leaves the rest of the
	// report intact.
	defer func() {
		if r := recover(); r != nil {
			adapters, err = nil, fmt.Errorf("GetAdaptersAddresses: %v", r)
		}
	}()

	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST

	size := uint32(15000)
	for range 3 {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))

		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}

		for adapter := first; adapter != nil; adapter = adapter.Next {
			adapters = append(adapters, adapter)
		}
		return adapters, nil
	}

	return nil, fmt.Errorf("GetAdaptersAddresses: buffer kept growing")
}

func closeKey(k registry.Key) {
	if err := k.Close(); err != nil {
		log.Debugf("close registry key: %v", err)
	}
}
