package listener

import "sync"

type CloseListener struct {
	listener func()
	mu       sync.Mutex
}

func NewCloseListener() *CloseListener {
	return &CloseListener{}
}

func (c *CloseListener) SetCloseListener(listener func()) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.listener = listener
}

func (c *CloseListener) Notify() {
	c.mu.Lock()

	if c.listener == nil {
		c.mu.Unlock()
		return
	}
	listener := c.listener
	c.mu.Unlock()

	listener()
}
