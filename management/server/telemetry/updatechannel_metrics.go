package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// UpdateChannelMetrics represents all metrics related to the UpdateChannel
type UpdateChannelMetrics struct {
	createChannelDurationMicro        metric.Int64Histogram
	closeChannelDurationMicro         metric.Int64Histogram
	closeChannelsDurationMicro        metric.Int64Histogram
	closeChannels                     metric.Int64Histogram
	sendUpdateDurationMicro           metric.Int64Histogram
	getAllConnectedPeersDurationMicro metric.Int64Histogram
	getAllConnectedPeers              metric.Int64Histogram
	hasChannelDurationMicro           metric.Int64Histogram
	ctx                               context.Context
}

// NewUpdateChannelMetrics creates an instance of UpdateChannel
func NewUpdateChannelMetrics(ctx context.Context, meter metric.Meter) (*UpdateChannelMetrics, error) {
	createChannelDurationMicro, err := meter.Int64Histogram("management.updatechannel.create.duration.micro")
	if err != nil {
		return nil, err
	}

	closeChannelDurationMicro, err := meter.Int64Histogram("management.updatechannel.close.one.duration.micro")
	if err != nil {
		return nil, err
	}

	closeChannelsDurationMicro, err := meter.Int64Histogram("management.updatechannel.close.multiple.duration.micro")
	if err != nil {
		return nil, err
	}

	closeChannels, err := meter.Int64Histogram("management.updatechannel.close.multiple.channels")
	if err != nil {
		return nil, err
	}

	sendUpdateDurationMicro, err := meter.Int64Histogram("management.updatechannel.send.duration.micro")
	if err != nil {
		return nil, err
	}

	getAllConnectedPeersDurationMicro, err := meter.Int64Histogram("management.updatechannel.get.all.duration.micro")
	if err != nil {
		return nil, err
	}

	getAllConnectedPeers, err := meter.Int64Histogram("management.updatechannel.get.all.peers")
	if err != nil {
		return nil, err
	}

	hasChannelDurationMicro, err := meter.Int64Histogram("management.updatechannel.haschannel.duration.micro")
	if err != nil {
		return nil, err
	}

	return &UpdateChannelMetrics{
		createChannelDurationMicro:        createChannelDurationMicro,
		closeChannelDurationMicro:         closeChannelDurationMicro,
		closeChannelsDurationMicro:        closeChannelsDurationMicro,
		closeChannels:                     closeChannels,
		sendUpdateDurationMicro:           sendUpdateDurationMicro,
		getAllConnectedPeersDurationMicro: getAllConnectedPeersDurationMicro,
		getAllConnectedPeers:              getAllConnectedPeers,
		hasChannelDurationMicro:           hasChannelDurationMicro,
		ctx:                               ctx,
	}, nil
}

// CountCreateChannelDuration counts the duration of the CreateChannel method,
// closed indicates if existing channel was closed before creation of a new one
func (metrics *UpdateChannelMetrics) CountCreateChannelDuration(duration time.Duration, closed bool) {
	opts := metric.WithAttributeSet(attribute.NewSet(attribute.Bool("closed", closed)))
	metrics.createChannelDurationMicro.Record(metrics.ctx, duration.Microseconds(), opts)
}

// CountCloseChannelDuration counts the duration of the CloseChannel method
func (metrics *UpdateChannelMetrics) CountCloseChannelDuration(duration time.Duration) {
	metrics.closeChannelDurationMicro.Record(metrics.ctx, duration.Microseconds())
}

// CountCloseChannelsDuration counts the duration of the CloseChannels method and the number of channels have been closed
func (metrics *UpdateChannelMetrics) CountCloseChannelsDuration(duration time.Duration, channels int) {
	metrics.closeChannelsDurationMicro.Record(metrics.ctx, duration.Microseconds())
	metrics.closeChannels.Record(metrics.ctx, int64(channels))
}

// CountSendUpdateDuration counts the duration of the SendUpdate method
// found indicates if peer had channel, dropped indicates if the message was dropped due channel buffer overload
func (metrics *UpdateChannelMetrics) CountSendUpdateDuration(duration time.Duration, found, dropped bool) {
	opts := metric.WithAttributeSet(attribute.NewSet(attribute.Bool("found", found), attribute.Bool("dropped", dropped)))
	metrics.sendUpdateDurationMicro.Record(metrics.ctx, duration.Microseconds(), opts)
}

// CountGetAllConnectedPeersDuration counts the duration of the GetAllConnectedPeers method and the number of peers have been returned
func (metrics *UpdateChannelMetrics) CountGetAllConnectedPeersDuration(duration time.Duration, peers int) {
	metrics.getAllConnectedPeersDurationMicro.Record(metrics.ctx, duration.Microseconds())
	metrics.getAllConnectedPeers.Record(metrics.ctx, int64(peers))
}

// CountHasChannelDuration counts the duration of the HasChannel method
func (metrics *UpdateChannelMetrics) CountHasChannelDuration(duration time.Duration) {
	metrics.hasChannelDurationMicro.Record(metrics.ctx, duration.Microseconds())
}
