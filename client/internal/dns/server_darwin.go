//go:build !ios

package dns

func (s *DefaultServer) initialize() (manager hostManager, err error) {
	m, err := newHostManager()
	if err != nil {
		return nil, err
	}
	m.wgInterface = s.wgInterface
	return m, nil
}
