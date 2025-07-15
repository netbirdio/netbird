package listener

type CloseListener struct {
	listener func()
}

func NewCloseListener() *CloseListener {
	return &CloseListener{}
}

func (c *CloseListener) SetCloseListener(listener func()) {
	c.listener = listener
}

func (c *CloseListener) Notify() {
	if c.listener != nil {
		c.listener()
	}
}
