package activity

type NoopEventStore struct {
}

func (store *NoopEventStore) Save(event *Event) (*Event, error) {
	event.ID = -1
	return event, nil
}

func (store *NoopEventStore) Get(accountID string, offset, limit int, descending bool) ([]*Event, error) {
	return []*Event{}, nil
}

func (store *NoopEventStore) Close() error {
	return nil
}
