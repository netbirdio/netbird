package dns

func (s *DefaultServer) initialize() (manager hostManager, err error) {
	// todo add ioDnsManager to constuctor
	return newHostManager(m.ioDnsManager)
}
