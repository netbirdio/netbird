package job

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// todo consider the channel buffer size when we allow to run multiple jobs
const jobChannelBuffer = 1

var (
	ErrJobChannelClosed = errors.New("job channel closed")
)

type Channel struct {
	events chan *Event
	once   sync.Once
}

func NewChannel() *Channel {
	jc := &Channel{
		events: make(chan *Event, jobChannelBuffer),
	}

	return jc
}

func (jc *Channel) AddEvent(ctx context.Context, responseWait time.Duration, event *Event) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
		// todo: timeout is handled in the wrong place. If the peer does not respond with the job response, the server does not clean it up from the pending jobs and cannot apply a new job
	case <-time.After(responseWait):
		return fmt.Errorf("failed to add the event to the channel")
	case jc.events <- event:
	}
	return nil
}

func (jc *Channel) Close() {
	jc.once.Do(func() {
		close(jc.events)
	})
}

func (jc *Channel) Event(ctx context.Context) (*Event, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case job, open := <-jc.events:
		if !open {
			return nil, ErrJobChannelClosed
		}
		return job, nil
	}
}
