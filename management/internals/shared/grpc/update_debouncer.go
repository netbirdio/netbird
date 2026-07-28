package grpc

import (
	"time"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
)

// UpdateDebouncer implements a backpressure mechanism that:
// - Sends the first update immediately
// - Coalesces rapid subsequent network map updates (only latest matters)
// - Queues control/config updates (all must be delivered)
// - Preserves the order of messages (important for control configs between network maps)
// - Ensures pending updates are sent after a quiet period
type UpdateDebouncer struct {
	debounceInterval time.Duration
	timer            *time.Timer
	pendingUpdates   []*network_map.UpdateMessage // Queue that preserves order
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

	// Already in debounce period, accumulate this update preserving order
	// Check if we should coalesce with the last pending update
	if len(d.pendingUpdates) > 0 &&
		update.MessageType == network_map.MessageTypeNetworkMap &&
		d.pendingUpdates[len(d.pendingUpdates)-1].MessageType == network_map.MessageTypeNetworkMap {
		// Replace the last network map with this one (coalesce consecutive network maps)
		d.pendingUpdates[len(d.pendingUpdates)-1] = update
	} else {
		// Append to the queue (preserves order for control configs and non-consecutive network maps)
		d.pendingUpdates = append(d.pendingUpdates, update)
	}
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

// GetPendingUpdates returns and clears all pending updates after timer expiration.
// Updates are returned in the order they were received, with consecutive network maps
// already coalesced to only the latest one.
// If there were pending updates, it restarts the timer to continue debouncing.
// If there were no pending updates, it clears the timer (true quiet period).
func (d *UpdateDebouncer) GetPendingUpdates() []*network_map.UpdateMessage {
	updates := d.pendingUpdates
	d.pendingUpdates = nil

	if len(updates) > 0 {
		// There were pending updates, so updates are still coming rapidly
		// Restart the timer to continue debouncing mode
		if d.timer != nil {
			d.timer.Reset(d.debounceInterval)
		}
	} else {
		// No pending updates means true quiet period - return to immediate mode
		d.timer = nil
		d.timerC = nil
	}

	return updates
}

// Stop stops the debouncer and cleans up resources
func (d *UpdateDebouncer) Stop() {
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
		d.timerC = nil
	}
	d.pendingUpdates = nil
}

func (d *UpdateDebouncer) startTimer() {
	d.timer = time.NewTimer(d.debounceInterval)
	d.timerC = d.timer.C
}

func (d *UpdateDebouncer) resetTimer() {
	d.timer.Stop()
	d.timer.Reset(d.debounceInterval)
}
