package bind

import (
	"runtime"

	"golang.org/x/net/ipv4"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

// todo: add close function
type worker struct {
	jobOffer    chan int
	numOfWorker int

	jobFn func(msg *ipv4.Message) (int, *StdNetEndpoint)

	messages []ipv4.Message
	sizes    []int
	eps      []wgConn.Endpoint
}

func newWorker(jobFn func(msg *ipv4.Message) (int, *StdNetEndpoint)) *worker {
	w := &worker{
		jobOffer:    make(chan int),
		numOfWorker: runtime.NumCPU(),
		jobFn:       jobFn,
	}

	w.populateWorkers()
	return w
}

func (w *worker) doWork(messages []ipv4.Message, sizes []int, eps []wgConn.Endpoint) {
	w.messages = messages
	w.sizes = sizes
	w.eps = eps

	for i := 0; i < len(messages); i++ {
		w.jobOffer <- i
	}
}

func (w *worker) populateWorkers() {
	for i := 0; i < w.numOfWorker; i++ {
		go w.loop()
	}
}

func (w *worker) loop() {
	for {
		select {
		case msgPos := <-w.jobOffer:
			w.sizes[msgPos], w.eps[msgPos] = w.jobFn(&w.messages[msgPos])
		}
	}
}
