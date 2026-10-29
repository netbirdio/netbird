//go:build android

package android

import "fmt"

type PeerRoutes struct {
	routes []string
}

func (p *PeerRoutes) Get(i int) (string, error) {
	if i < 0 || i >= len(p.routes) {
		return "", fmt.Errorf("%d is out of range", i)
	}
	return p.routes[i], nil
}

func (p *PeerRoutes) Size() int {
	return len(p.routes)
}
