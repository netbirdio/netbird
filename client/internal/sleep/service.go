package sleep

type detector interface {
	Register(callback func()) error
	Deregister() error
}

type Service struct {
	detector detector
}

func New() (*Service, error) {
	d, err := NewDetector()
	if err != nil {
		return nil, err
	}

	return &Service{
		detector: d,
	}, nil
}

func (s *Service) Register(callback func()) error {
	return s.detector.Register(callback)
}

func (s *Service) Deregister() error {
	return s.detector.Deregister()
}
