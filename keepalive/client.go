package keepalive

func IsKeepAliveMsg(body []byte) bool {
	return len(body) == 0
}
