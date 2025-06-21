package inactivity

import (
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type Recorder struct {
	mu       sync.Mutex
	file     *os.File
	filename string
}

func NewRecorder() *Recorder {
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("inactivity_log_%s.txt", timestamp)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Errorf("error opening file: %v", err)
	}

	return &Recorder{
		file:     file,
		filename: filename,
	}
}

func (r *Recorder) ReceivedBytes(peer string, now time.Time, bytes int64) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry := fmt.Sprintf("%s; %s; %d\n", now.Format(time.RFC3339), peer, bytes)
	_, err := r.file.WriteString(entry)
	if err != nil {
		log.Errorf("error writing to file: %v", err)
	}
}

func (r *Recorder) Close() {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.file.Close(); err != nil {
		log.Errorf("error closing file: %v", err)
	}
}
