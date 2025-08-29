//go:build (linux && !android) || freebsd

package dns

func (s *DefaultServer) initialize() (manager hostManager, err error) {
	return newHostManager(s.wgInterface.Name())
}
