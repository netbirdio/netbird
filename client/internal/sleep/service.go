package sleep

var (
	EventTypeUnknown EventType = 0
	EventTypeSleep   EventType = 1
	EventTypeWakeUp  EventType = 2
)

type EventType int

type detector interface {
	Register(callback func(eventType EventType)) error
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

func (s *Service) Register(callback func(eventType EventType)) error {
	return s.detector.Register(callback)
}

func (s *Service) Deregister() error {
	return s.detector.Deregister()
}
