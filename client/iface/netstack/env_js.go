package netstack

const EnvUseNetstackMode = "NB_USE_NETSTACK_MODE"

// IsEnabled always returns true for js since it's the only mode available
func IsEnabled() bool {
	return true
}

func ListenAddr() string {
	return ""
}
