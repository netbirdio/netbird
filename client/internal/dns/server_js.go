package dns

func (s *DefaultServer) initialize() (hostManager, error) {
	return &noopHostConfigurator{}, nil
}
