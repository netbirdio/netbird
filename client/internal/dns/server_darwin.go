//go:build !ios

package dns

// initialize creates the macOS scutil host manager and wires the overlay interface into it.
func (s *DefaultServer) initialize() (manager hostManager, err error) {
	m, err := newHostManager()
	if err != nil {
		return nil, err
	}
	m.wgInterface = s.wgInterface
	return m, nil
}
