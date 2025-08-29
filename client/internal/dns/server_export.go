package dns

import (
	"fmt"
	"sync"
)

var (
	mutex  sync.Mutex
	server Server
)

// GetServerDns export the DNS server instance in static way. It used by the Mobile client
func GetServerDns() (Server, error) {
	mutex.Lock()
	if server == nil {
		mutex.Unlock()
		return nil, fmt.Errorf("DNS server not instantiated yet")
	}
	s := server
	mutex.Unlock()
	return s, nil
}

func setServerDns(newServerServer Server) {
	mutex.Lock()
	server = newServerServer
	defer mutex.Unlock()
}
