package manager

// Manager is used to load multiple eBPF programs. E.g., the WireGuard proxy
type Manager interface {
	LoadWgProxy(proxyPort, wgPort int) error
	FreeWGProxy() error
}
