package manager

// Manager is used to load multiple eBPF programs. E.g., current DNS programs and WireGuard proxy
type Manager interface {
	LoadDNSFwd(ip string, dnsPort int) error
	FreeDNSFwd() error
	LoadWgProxy(proxyPort, wgPort int) error
	FreeWGProxy() error
}
