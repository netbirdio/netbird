package sleep

import (
	"context"
)

type detector interface {
	Register() error
	Deregister() error
	Listen(ctx context.Context) error
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

func (s *Service) Register() error {
	return s.detector.Register()
}

func (s *Service) Deregister() error {
	return s.detector.Deregister()
}

func (s *Service) Listen(ctx context.Context) error {
	return s.detector.Listen(ctx)
}
