package ws

import "golang.org/x/sys/unix"

// keepAliveIdleOpt is the TCP option for the keepalive idle time.
const keepAliveIdleOpt = unix.TCP_KEEPALIVE
