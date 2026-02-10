package grpc

import (
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestUpdateDebouncer_FirstUpdateSentImmediately(t *testing.T) {
	debouncer := NewUpdateDebouncer(50 * time.Millisecond)
	defer debouncer.Stop()

	update := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}

	shouldSend := debouncer.ProcessUpdate(update)

	if !shouldSend {
		t.Error("First update should be sent immediately")
	}

	if debouncer.TimerChannel() == nil {
		t.Error("Timer should be started after first update")
	}
}

func TestUpdateDebouncer_RapidUpdatesCoalesced(t *testing.T) {
	debouncer := NewUpdateDebouncer(50 * time.Millisecond)
	defer debouncer.Stop()

	update1 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	update2 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	update3 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}

	// First update should be sent immediately
	if !debouncer.ProcessUpdate(update1) {
		t.Error("First update should be sent immediately")
	}

	// Rapid subsequent updates should be coalesced
	if debouncer.ProcessUpdate(update2) {
		t.Error("Second rapid update should not be sent immediately")
	}

	if debouncer.ProcessUpdate(update3) {
		t.Error("Third rapid update should not be sent immediately")
	}

	// Wait for debounce period
	select {
	case <-debouncer.TimerChannel():
		pendingUpdates := debouncer.GetPendingUpdates()
		if len(pendingUpdates) != 1 {
			t.Errorf("Should get exactly 1 pending update, got %d", len(pendingUpdates))
		}
		if pendingUpdates[0] != update3 {
			t.Error("Should get the last update (update3)")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Timer should have fired")
	}
}

func TestUpdateDebouncer_LastUpdateAlwaysSent(t *testing.T) {
	debouncer := NewUpdateDebouncer(30 * time.Millisecond)
	defer debouncer.Stop()

	update1 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	update2 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}

	// Send first update
	debouncer.ProcessUpdate(update1)

	// Send second update within debounce period
	debouncer.ProcessUpdate(update2)

	// Wait for timer
	select {
	case <-debouncer.TimerChannel():
		pendingUpdates := debouncer.GetPendingUpdates()
		if len(pendingUpdates) != 1 {
			t.Errorf("Should get exactly 1 pending update, got %d", len(pendingUpdates))
		}
		if pendingUpdates[0] != update2 {
			t.Error("Should get the last update")
		}
		if pendingUpdates[0] == update1 {
			t.Error("Should not get the first update")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Timer should have fired")
	}
}

func TestUpdateDebouncer_TimerResetOnNewUpdate(t *testing.T) {
	debouncer := NewUpdateDebouncer(50 * time.Millisecond)
	defer debouncer.Stop()

	update1 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	update2 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	update3 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}

	// Send first update
	debouncer.ProcessUpdate(update1)

	// Wait a bit, but not the full debounce period
	time.Sleep(30 * time.Millisecond)

	// Send second update - should reset timer
	debouncer.ProcessUpdate(update2)

	// Wait a bit more
	time.Sleep(30 * time.Millisecond)

	// Send third update - should reset timer again
	debouncer.ProcessUpdate(update3)

	// Now wait for the timer (should fire after last update's reset)
	select {
	case <-debouncer.TimerChannel():
		pendingUpdates := debouncer.GetPendingUpdates()
		if len(pendingUpdates) != 1 {
			t.Errorf("Should get exactly 1 pending update, got %d", len(pendingUpdates))
		}
		if pendingUpdates[0] != update3 {
			t.Error("Should get the last update (update3)")
		}
		// Timer should be restarted since there was a pending update
		if debouncer.TimerChannel() == nil {
			t.Error("Timer should be restarted after sending pending update")
		}
	case <-time.After(150 * time.Millisecond):
		t.Error("Timer should have fired")
	}
}

func TestUpdateDebouncer_TimerRestartsAfterPendingUpdateSent(t *testing.T) {
	debouncer := NewUpdateDebouncer(30 * time.Millisecond)
	defer debouncer.Stop()

	update1 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	update2 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	update3 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}

	// First update sent immediately
	debouncer.ProcessUpdate(update1)

	// Second update coalesced
	debouncer.ProcessUpdate(update2)

	// Wait for timer to expire
	select {
	case <-debouncer.TimerChannel():
		pendingUpdates := debouncer.GetPendingUpdates()

		if len(pendingUpdates) == 0 {
			t.Fatal("Should have pending update")
		}

		// After sending pending update, timer is restarted, so next update is NOT immediate
		if debouncer.ProcessUpdate(update3) {
			t.Error("Update after debounced send should not be sent immediately (timer restarted)")
		}

		// Wait for the restarted timer and verify update3 is pending
		select {
		case <-debouncer.TimerChannel():
			finalUpdates := debouncer.GetPendingUpdates()
			if len(finalUpdates) != 1 || finalUpdates[0] != update3 {
				t.Error("Should get update3 as pending")
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Timer should have fired for restarted timer")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Timer should have fired")
	}
}

func TestUpdateDebouncer_StopCleansUp(t *testing.T) {
	debouncer := NewUpdateDebouncer(50 * time.Millisecond)

	update := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}

	// Send update to start timer
	debouncer.ProcessUpdate(update)

	// Stop should clean up
	debouncer.Stop()

	// Multiple stops should be safe
	debouncer.Stop()
}

func TestUpdateDebouncer_HighFrequencyUpdates(t *testing.T) {
	debouncer := NewUpdateDebouncer(50 * time.Millisecond)
	defer debouncer.Stop()

	// Simulate high-frequency updates
	var lastUpdate *network_map.UpdateMessage
	sentImmediately := 0
	for i := 0; i < 100; i++ {
		update := &network_map.UpdateMessage{
			Update: &proto.SyncResponse{
				NetworkMap: &proto.NetworkMap{
					Serial: uint64(i),
				},
			},
			MessageType: network_map.MessageTypeNetworkMap,
		}
		lastUpdate = update
		if debouncer.ProcessUpdate(update) {
			sentImmediately++
		}
		time.Sleep(1 * time.Millisecond) // Very rapid updates
	}

	// Only first update should be sent immediately
	if sentImmediately != 1 {
		t.Errorf("Expected only 1 update sent immediately, got %d", sentImmediately)
	}

	// Wait for debounce period
	select {
	case <-debouncer.TimerChannel():
		pendingUpdates := debouncer.GetPendingUpdates()
		if len(pendingUpdates) != 1 {
			t.Errorf("Should get exactly 1 pending update, got %d", len(pendingUpdates))
		}
		if pendingUpdates[0] != lastUpdate {
			t.Error("Should get the very last update")
		}
		if pendingUpdates[0].Update.NetworkMap.Serial != 99 {
			t.Errorf("Expected serial 99, got %d", pendingUpdates[0].Update.NetworkMap.Serial)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Timer should have fired")
	}
}

func TestUpdateDebouncer_NoUpdatesAfterFirst(t *testing.T) {
	debouncer := NewUpdateDebouncer(30 * time.Millisecond)
	defer debouncer.Stop()

	update := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}

	// Send first update
	if !debouncer.ProcessUpdate(update) {
		t.Error("First update should be sent immediately")
	}

	// Wait for timer to expire with no additional updates (true quiet period)
	select {
	case <-debouncer.TimerChannel():
		pendingUpdates := debouncer.GetPendingUpdates()
		if len(pendingUpdates) != 0 {
			t.Error("Should have no pending updates")
		}
		// After true quiet period, timer should be cleared
		if debouncer.TimerChannel() != nil {
			t.Error("Timer should be cleared after quiet period")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Timer should have fired")
	}
}

func TestUpdateDebouncer_IntermediateUpdatesDropped(t *testing.T) {
	debouncer := NewUpdateDebouncer(50 * time.Millisecond)
	defer debouncer.Stop()

	updates := make([]*network_map.UpdateMessage, 5)
	for i := range updates {
		updates[i] = &network_map.UpdateMessage{
			Update: &proto.SyncResponse{
				NetworkMap: &proto.NetworkMap{
					Serial: uint64(i),
				},
			},
			MessageType: network_map.MessageTypeNetworkMap,
		}
	}

	// First update sent immediately
	debouncer.ProcessUpdate(updates[0])

	// Send updates 1, 2, 3, 4 rapidly - only last one should remain pending
	debouncer.ProcessUpdate(updates[1])
	debouncer.ProcessUpdate(updates[2])
	debouncer.ProcessUpdate(updates[3])
	debouncer.ProcessUpdate(updates[4])

	// Wait for debounce
	<-debouncer.TimerChannel()
	pendingUpdates := debouncer.GetPendingUpdates()

	if len(pendingUpdates) != 1 {
		t.Errorf("Should get exactly 1 pending update, got %d", len(pendingUpdates))
	}
	if pendingUpdates[0].Update.NetworkMap.Serial != 4 {
		t.Errorf("Expected only the last update (serial 4), got serial %d", pendingUpdates[0].Update.NetworkMap.Serial)
	}
}

func TestUpdateDebouncer_TrueQuietPeriodResetsToImmediateMode(t *testing.T) {
	debouncer := NewUpdateDebouncer(30 * time.Millisecond)
	defer debouncer.Stop()

	update1 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	update2 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{},
		MessageType: network_map.MessageTypeNetworkMap,
	}

	// First update sent immediately
	if !debouncer.ProcessUpdate(update1) {
		t.Error("First update should be sent immediately")
	}

	// Wait for timer without sending any more updates (true quiet period)
	<-debouncer.TimerChannel()
	pendingUpdates := debouncer.GetPendingUpdates()

	if len(pendingUpdates) != 0 {
		t.Error("Should have no pending updates during quiet period")
	}

	// After true quiet period, next update should be sent immediately
	if !debouncer.ProcessUpdate(update2) {
		t.Error("Update after true quiet period should be sent immediately")
	}
}

func TestUpdateDebouncer_ContinuousHighFrequencyStaysInDebounceMode(t *testing.T) {
	debouncer := NewUpdateDebouncer(50 * time.Millisecond)
	defer debouncer.Stop()

	// Simulate continuous high-frequency updates
	for i := 0; i < 10; i++ {
		update := &network_map.UpdateMessage{
			Update: &proto.SyncResponse{
				NetworkMap: &proto.NetworkMap{
					Serial: uint64(i),
				},
			},
			MessageType: network_map.MessageTypeNetworkMap,
		}

		if i == 0 {
			// First one sent immediately
			if !debouncer.ProcessUpdate(update) {
				t.Error("First update should be sent immediately")
			}
		} else {
			// All others should be coalesced (not sent immediately)
			if debouncer.ProcessUpdate(update) {
				t.Errorf("Update %d should not be sent immediately", i)
			}
		}

		// Wait a bit but send next update before debounce expires
		time.Sleep(20 * time.Millisecond)
	}

	// Now wait for final debounce
	select {
	case <-debouncer.TimerChannel():
		pendingUpdates := debouncer.GetPendingUpdates()
		if len(pendingUpdates) == 0 {
			t.Fatal("Should have the last update pending")
		}
		if pendingUpdates[0].Update.NetworkMap.Serial != 9 {
			t.Errorf("Expected serial 9, got %d", pendingUpdates[0].Update.NetworkMap.Serial)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Timer should have fired")
	}
}

func TestUpdateDebouncer_ControlConfigMessagesQueued(t *testing.T) {
	debouncer := NewUpdateDebouncer(50 * time.Millisecond)
	defer debouncer.Stop()

	netmapUpdate := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetworkMap: &proto.NetworkMap{Serial: 1}},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	tokenUpdate1 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetbirdConfig: &proto.NetbirdConfig{}},
		MessageType: network_map.MessageTypeControlConfig,
	}
	tokenUpdate2 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetbirdConfig: &proto.NetbirdConfig{}},
		MessageType: network_map.MessageTypeControlConfig,
	}

	// First update sent immediately
	debouncer.ProcessUpdate(netmapUpdate)

	// Send multiple control config updates - they should all be queued
	debouncer.ProcessUpdate(tokenUpdate1)
	debouncer.ProcessUpdate(tokenUpdate2)

	// Wait for debounce period
	select {
	case <-debouncer.TimerChannel():
		pendingUpdates := debouncer.GetPendingUpdates()
		// Should get both control config updates
		if len(pendingUpdates) != 2 {
			t.Errorf("Expected 2 control config updates, got %d", len(pendingUpdates))
		}
		// Control configs should come first
		if pendingUpdates[0] != tokenUpdate1 {
			t.Error("First pending update should be tokenUpdate1")
		}
		if pendingUpdates[1] != tokenUpdate2 {
			t.Error("Second pending update should be tokenUpdate2")
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Timer should have fired")
	}
}

func TestUpdateDebouncer_MixedMessageTypes(t *testing.T) {
	debouncer := NewUpdateDebouncer(50 * time.Millisecond)
	defer debouncer.Stop()

	netmapUpdate1 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetworkMap: &proto.NetworkMap{Serial: 1}},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	netmapUpdate2 := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetworkMap: &proto.NetworkMap{Serial: 2}},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	tokenUpdate := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetbirdConfig: &proto.NetbirdConfig{}},
		MessageType: network_map.MessageTypeControlConfig,
	}

	// First update sent immediately
	debouncer.ProcessUpdate(netmapUpdate1)

	// Send token update and network map update
	debouncer.ProcessUpdate(tokenUpdate)
	debouncer.ProcessUpdate(netmapUpdate2)

	// Wait for debounce period
	select {
	case <-debouncer.TimerChannel():
		pendingUpdates := debouncer.GetPendingUpdates()
		// Should get 2 updates in order: token, then network map
		if len(pendingUpdates) != 2 {
			t.Errorf("Expected 2 pending updates, got %d", len(pendingUpdates))
		}
		// Token update should come first (preserves order)
		if pendingUpdates[0] != tokenUpdate {
			t.Error("First pending update should be tokenUpdate")
		}
		// Network map update should come second
		if pendingUpdates[1] != netmapUpdate2 {
			t.Error("Second pending update should be netmapUpdate2")
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Timer should have fired")
	}
}

func TestUpdateDebouncer_OrderPreservation(t *testing.T) {
	debouncer := NewUpdateDebouncer(50 * time.Millisecond)
	defer debouncer.Stop()

	// Simulate: 50 network maps -> 1 control config -> 50 network maps
	// Expected result: 3 messages (netmap, controlConfig, netmap)

	// Send first network map immediately
	firstNetmap := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetworkMap: &proto.NetworkMap{Serial: 0}},
		MessageType: network_map.MessageTypeNetworkMap,
	}
	if !debouncer.ProcessUpdate(firstNetmap) {
		t.Error("First update should be sent immediately")
	}

	// Send 49 more network maps (will be coalesced to last one)
	var lastNetmapBatch1 *network_map.UpdateMessage
	for i := 1; i < 50; i++ {
		lastNetmapBatch1 = &network_map.UpdateMessage{
			Update:      &proto.SyncResponse{NetworkMap: &proto.NetworkMap{Serial: uint64(i)}},
			MessageType: network_map.MessageTypeNetworkMap,
		}
		debouncer.ProcessUpdate(lastNetmapBatch1)
	}

	// Send 1 control config
	controlConfig := &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetbirdConfig: &proto.NetbirdConfig{}},
		MessageType: network_map.MessageTypeControlConfig,
	}
	debouncer.ProcessUpdate(controlConfig)

	// Send 50 more network maps (will be coalesced to last one)
	var lastNetmapBatch2 *network_map.UpdateMessage
	for i := 50; i < 100; i++ {
		lastNetmapBatch2 = &network_map.UpdateMessage{
			Update:      &proto.SyncResponse{NetworkMap: &proto.NetworkMap{Serial: uint64(i)}},
			MessageType: network_map.MessageTypeNetworkMap,
		}
		debouncer.ProcessUpdate(lastNetmapBatch2)
	}

	// Wait for debounce period
	select {
	case <-debouncer.TimerChannel():
		pendingUpdates := debouncer.GetPendingUpdates()
		// Should get exactly 3 updates: netmap, controlConfig, netmap
		if len(pendingUpdates) != 3 {
			t.Errorf("Expected 3 pending updates, got %d", len(pendingUpdates))
		}
		// First should be the last netmap from batch 1
		if pendingUpdates[0] != lastNetmapBatch1 {
			t.Error("First pending update should be last netmap from batch 1")
		}
		if pendingUpdates[0].Update.NetworkMap.Serial != 49 {
			t.Errorf("Expected serial 49, got %d", pendingUpdates[0].Update.NetworkMap.Serial)
		}
		// Second should be the control config
		if pendingUpdates[1] != controlConfig {
			t.Error("Second pending update should be control config")
		}
		// Third should be the last netmap from batch 2
		if pendingUpdates[2] != lastNetmapBatch2 {
			t.Error("Third pending update should be last netmap from batch 2")
		}
		if pendingUpdates[2].Update.NetworkMap.Serial != 99 {
			t.Errorf("Expected serial 99, got %d", pendingUpdates[2].Update.NetworkMap.Serial)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Timer should have fired")
	}
}
