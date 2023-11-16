package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/instrument/syncint64"
)

// UpdateChannelMetrics represents all metrics related to the UpdateChannel
type UpdateChannelMetrics struct {
	createChannelDurationMs           syncint64.Histogram
	createChannelDurationMicro        syncint64.Histogram
	closeChannelDurationMs            syncint64.Histogram
	closeChannelDurationMicro         syncint64.Histogram
	closeChannelsDurationMs           syncint64.Histogram
	closeChannelsDurationMicro        syncint64.Histogram
	closeChannels                     syncint64.Histogram
	sendUpdateDurationMs              syncint64.Histogram
	sendUpdateDurationMicro           syncint64.Histogram
	getAllConnectedPeersDurationMs    syncint64.Histogram
	getAllConnectedPeersDurationMicro syncint64.Histogram
	getAllConnectedPeers              syncint64.Histogram
	ctx                               context.Context
}

// NewUpdateChannelMetrics creates an instance of UpdateChannel
func NewUpdateChannelMetrics(ctx context.Context, meter metric.Meter) (*UpdateChannelMetrics, error) {
	createChannelDurationMs, err := meter.SyncInt64().Histogram("management.updatechannel.create.duration.ms")
	if err != nil {
		return nil, err
	}

	createChannelDurationMicro, err := meter.SyncInt64().Histogram("management.updatechannel.create.duration.micro")
	if err != nil {
		return nil, err
	}

	closeChannelDurationMs, err := meter.SyncInt64().Histogram("management.updatechannel.close.one.duration.ms")
	if err != nil {
		return nil, err
	}

	closeChannelDurationMicro, err := meter.SyncInt64().Histogram("management.updatechannel.close.one.duration.micro")
	if err != nil {
		return nil, err
	}

	closeChannelsDurationMs, err := meter.SyncInt64().Histogram("management.updatechannel.close.multiple.duration.ms")
	if err != nil {
		return nil, err
	}

	closeChannelsDurationMicro, err := meter.SyncInt64().Histogram("management.updatechannel.close.multiple.duration.micro")
	if err != nil {
		return nil, err
	}

	closeChannels, err := meter.SyncInt64().Histogram("management.updatechannel.close.multiple.channels")
	if err != nil {
		return nil, err
	}

	sendUpdateDurationMs, err := meter.SyncInt64().Histogram("management.updatechannel.send.duration.ms")
	if err != nil {
		return nil, err
	}

	sendUpdateDurationMicro, err := meter.SyncInt64().Histogram("management.updatechannel.send.duration.micro")
	if err != nil {
		return nil, err
	}

	getAllConnectedPeersDurationMs, err := meter.SyncInt64().Histogram("management.updatechannel.get.all.duration.ms")
	if err != nil {
		return nil, err
	}

	getAllConnectedPeersDurationMicro, err := meter.SyncInt64().Histogram("management.updatechannel.get.all.duration.micro")
	if err != nil {
		return nil, err
	}

	getAllConnectedPeers, err := meter.SyncInt64().Histogram("management.updatechannel.get.all.peers")
	if err != nil {
		return nil, err
	}

	return &UpdateChannelMetrics{
		createChannelDurationMs:           createChannelDurationMs,
		createChannelDurationMicro:        createChannelDurationMicro,
		closeChannelDurationMs:            closeChannelDurationMs,
		closeChannelDurationMicro:         closeChannelDurationMicro,
		closeChannelsDurationMs:           closeChannelsDurationMs,
		closeChannelsDurationMicro:        closeChannelsDurationMicro,
		closeChannels:                     closeChannels,
		sendUpdateDurationMs:              sendUpdateDurationMs,
		sendUpdateDurationMicro:           sendUpdateDurationMicro,
		getAllConnectedPeersDurationMs:    getAllConnectedPeersDurationMs,
		getAllConnectedPeersDurationMicro: getAllConnectedPeersDurationMicro,
		getAllConnectedPeers:              getAllConnectedPeers,
		ctx:                               ctx,
	}, nil
}

// CountCreateChannelDuration counts the duration of the CreateChannel method,
// closed indicates if existing channel was closed before creation of a new one
func (metrics *UpdateChannelMetrics) CountCreateChannelDuration(duration time.Duration, closed bool) {
	metrics.createChannelDurationMs.Record(metrics.ctx, duration.Milliseconds(), attribute.Bool("closed", closed))
	metrics.createChannelDurationMicro.Record(metrics.ctx, duration.Microseconds(), attribute.Bool("closed", closed))
}

// CountCloseChannelDuration counts the duration of the CloseChannel method
func (metrics *UpdateChannelMetrics) CountCloseChannelDuration(duration time.Duration) {
	metrics.closeChannelDurationMs.Record(metrics.ctx, duration.Milliseconds())
	metrics.closeChannelDurationMicro.Record(metrics.ctx, duration.Microseconds())
}

// CountCloseChannelsDuration counts the duration of the CloseChannels method and the number of channels have been closed
func (metrics *UpdateChannelMetrics) CountCloseChannelsDuration(duration time.Duration, channels int) {
	metrics.closeChannelsDurationMs.Record(metrics.ctx, duration.Milliseconds())
	metrics.closeChannelsDurationMicro.Record(metrics.ctx, duration.Microseconds())
	metrics.closeChannels.Record(metrics.ctx, int64(channels))
}

// CountSendUpdateDuration counts the duration of the SendUpdate method
// found indicates if peer had channel, dropped indicates if the message was dropped due channel buffer overload
func (metrics *UpdateChannelMetrics) CountSendUpdateDuration(duration time.Duration, found, dropped bool) {
	attrs := []attribute.KeyValue{attribute.Bool("found", found), attribute.Bool("dropped", dropped)}
	metrics.sendUpdateDurationMs.Record(metrics.ctx, duration.Milliseconds(), attrs...)
	metrics.sendUpdateDurationMicro.Record(metrics.ctx, duration.Microseconds(), attrs...)
}

// CountGetAllConnectedPeersDuration counts the duration of the GetAllConnectedPeers method and the number of peers have been returned
func (metrics *UpdateChannelMetrics) CountGetAllConnectedPeersDuration(duration time.Duration, peers int) {
	metrics.getAllConnectedPeersDurationMs.Record(metrics.ctx, duration.Milliseconds())
	metrics.getAllConnectedPeersDurationMicro.Record(metrics.ctx, duration.Microseconds())
	metrics.getAllConnectedPeers.Record(metrics.ctx, int64(peers))
}
