package internal

import "sync"

// A Cond is a condition variable like sync.Cond, but using a channel so we can use select.
type Cond struct {
	once sync.Once
	C    chan struct{}
}

// NewCond creates a new condition variable.
func NewCond() *Cond {
	return &Cond{C: make(chan struct{})}
}

// Do runs f if the condition hasn't been signaled yet. Afterwards it will be signaled.
func (c *Cond) Do(f func()) {
	c.once.Do(func() {
		f()
		close(c.C)
	})
}

// Signal closes the condition variable channel.
func (c *Cond) Signal() {
	c.Do(func() {})
}

// Wait waits for the condition variable channel to close.
func (c *Cond) Wait() {
	<-c.C
}
