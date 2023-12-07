package dns

func (s *DefaultServer) initialize() (manager hostManager, err error) {
	err = s.service.Listen()
	if err != nil {
		return err
	}

	return newHostManager()
}
