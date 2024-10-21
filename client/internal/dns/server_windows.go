package dns

func (s *DefaultServer) initialize() (hostManager, error) {
	return newHostManager(s.wgInterface)
}
