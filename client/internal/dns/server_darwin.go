//go:build !ios

package dns

func (s *DefaultServer) initialize() (manager hostManager, err error) {
	return newHostManager()
}
