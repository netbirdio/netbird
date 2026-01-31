package grpc

import (
	"time"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
)

// UpdateDebouncer implements a backpressure mechanism that:
// - Sends the first update immediately
// - Coalesces rapid subsequent updates
// - Ensures the last update is always sent after a quiet period
type UpdateDebouncer struct {
	debounceInterval time.Duration
	timer            *time.Timer
	pendingUpdate    *network_map.UpdateMessage
	timerC           <-chan time.Time
}

// NewUpdateDebouncer creates a new debouncer with the specified interval
func NewUpdateDebouncer(interval time.Duration) *UpdateDebouncer {
	return &UpdateDebouncer{
		debounceInterval: interval,
	}
}

// ProcessUpdate handles an incoming update and returns whether it should be sent immediately
func (d *UpdateDebouncer) ProcessUpdate(update *network_map.UpdateMessage) bool {
	if d.timer == nil {
		// No active debounce timer, signal to send immediately
		// and start the debounce period
		d.startTimer()
		return true
	}

	// Already in debounce period, accumulate this update (dropping previous pending)
	d.pendingUpdate = update
	d.resetTimer()
	return false
}

// TimerChannel returns the timer channel for select statements
func (d *UpdateDebouncer) TimerChannel() <-chan time.Time {
	if d.timer == nil {
		return nil
	}
	return d.timerC
}

// GetPendingUpdate returns and clears the pending update after timer expiration
// If there was a pending update, it restarts the timer to continue debouncing.
// If there was no pending update, it clears the timer (true quiet period).
func (d *UpdateDebouncer) GetPendingUpdate() *network_map.UpdateMessage {
	update := d.pendingUpdate
	d.pendingUpdate = nil

	if update != nil {
		// There was a pending update, so updates are still coming rapidly
		// Restart the timer to continue debouncing mode
		if d.timer != nil {
			d.timer.Reset(d.debounceInterval)
		}
	} else {
		// No pending update means true quiet period - return to immediate mode
		d.timer = nil
		d.timerC = nil
	}

	return update
}

// Stop stops the debouncer and cleans up resources
func (d *UpdateDebouncer) Stop() {
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
		d.timerC = nil
	}
}

func (d *UpdateDebouncer) startTimer() {
	d.timer = time.NewTimer(d.debounceInterval)
	d.timerC = d.timer.C
}

func (d *UpdateDebouncer) resetTimer() {
	if !d.timer.Stop() {
		// Timer already fired, drain the channel
		select {
		case <-d.timerC:
		default:
		}
	}
	d.timer.Reset(d.debounceInterval)
}
