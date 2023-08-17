package ebpf

type Manager interface {
	LoadDNSFwd(fakeIP, dnsIP string, dnsPort int) error
	FreeDNSFwd() error
	LoadWgProxy(proxyPort, wgPort int) error
	FreeWGProxy() error
}
