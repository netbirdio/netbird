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
	calcPostureChecksDurationMicro    metric.Int64Histogram
	calcPeerNetworkMapDurationMs      metric.Int64Histogram
	mergeNetworkMapDurationMicro      metric.Int64Histogram
	toSyncResponseDurationMicro       metric.Int64Histogram
	bufferPushCounter                 metric.Int64Counter
	bufferOverwriteCounter            metric.Int64Counter
	bufferIgnoreCounter               metric.Int64Counter
	ctx                               context.Context
}

// NewUpdateChannelMetrics creates an instance of UpdateChannel
func NewUpdateChannelMetrics(ctx context.Context, meter metric.Meter) (*UpdateChannelMetrics, error) {
	createChannelDurationMicro, err := meter.Int64Histogram("management.updatechannel.create.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to create a new peer update channel"),
	)
	if err != nil {
		return nil, err
	}

	closeChannelDurationMicro, err := meter.Int64Histogram("management.updatechannel.close.one.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to close a peer update channel"),
	)
	if err != nil {
		return nil, err
	}

	closeChannelsDurationMicro, err := meter.Int64Histogram("management.updatechannel.close.multiple.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to close a set of peer update channels"),
	)

	if err != nil {
		return nil, err
	}

	closeChannels, err := meter.Int64Histogram("management.updatechannel.close.multiple.channels",
		metric.WithUnit("1"),
		metric.WithDescription("Number of peer update channels that have been closed"),
	)

	if err != nil {
		return nil, err
	}

	sendUpdateDurationMicro, err := meter.Int64Histogram("management.updatechannel.send.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to send an network map update to a peer"),
	)
	if err != nil {
		return nil, err
	}

	getAllConnectedPeersDurationMicro, err := meter.Int64Histogram("management.updatechannel.get.all.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to get all connected peers"),
	)
	if err != nil {
		return nil, err
	}

	getAllConnectedPeers, err := meter.Int64Histogram("management.updatechannel.get.all.peers",
		metric.WithUnit("1"),
		metric.WithDescription("Number of connected peers"),
	)
	if err != nil {
		return nil, err
	}

	hasChannelDurationMicro, err := meter.Int64Histogram("management.updatechannel.haschannel.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to check if a peer has a channel"),
	)
	if err != nil {
		return nil, err
	}

	calcPostureChecksDurationMicro, err := meter.Int64Histogram("management.updatechannel.calc.posturechecks.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to get the posture checks for a peer"),
	)
	if err != nil {
		return nil, err
	}

	calcPeerNetworkMapDurationMs, err := meter.Int64Histogram("management.updatechannel.calc.networkmap.duration.ms",
		metric.WithUnit("milliseconds"),
		metric.WithDescription("Duration of how long it takes to calculate the network map for a peer"),
	)
	if err != nil {
		return nil, err
	}

	mergeNetworkMapDurationMicro, err := meter.Int64Histogram("management.updatechannel.merge.networkmap.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to merge the network maps for a peer"),
	)
	if err != nil {
		return nil, err
	}

	toSyncResponseDurationMicro, err := meter.Int64Histogram("management.updatechannel.tosyncresponse.duration.micro",
		metric.WithUnit("microseconds"),
		metric.WithDescription("Duration of how long it takes to convert the network map to sync response"),
	)
	if err != nil {
		return nil, err
	}

	bufferPushCounter, err := meter.Int64Counter("management.updatechannel.buffer.push.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of updates pushed to an empty buffer"))
	if err != nil {
		return nil, err
	}

	bufferOverwriteCounter, err := meter.Int64Counter("management.updatechannel.buffer.overwrite.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of updates overwriting old unsent updates in the buffer"))
	if err != nil {
		return nil, err
	}

	bufferIgnoreCounter, err := meter.Int64Counter("management.updatechannel.buffer.ignore.counter",
		metric.WithUnit("1"),
		metric.WithDescription("Number of updates being ignored due to old network serial"))
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
		calcPostureChecksDurationMicro:    calcPostureChecksDurationMicro,
		calcPeerNetworkMapDurationMs:      calcPeerNetworkMapDurationMs,
		mergeNetworkMapDurationMicro:      mergeNetworkMapDurationMicro,
		toSyncResponseDurationMicro:       toSyncResponseDurationMicro,
		bufferPushCounter:                 bufferPushCounter,
		bufferOverwriteCounter:            bufferOverwriteCounter,
		bufferIgnoreCounter:               bufferIgnoreCounter,
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

func (metrics *UpdateChannelMetrics) CountCalcPostureChecksDuration(duration time.Duration) {
	metrics.calcPostureChecksDurationMicro.Record(metrics.ctx, duration.Microseconds())
}

func (metrics *UpdateChannelMetrics) CountCalcPeerNetworkMapDuration(duration time.Duration) {
	metrics.calcPeerNetworkMapDurationMs.Record(metrics.ctx, duration.Milliseconds())
}

func (metrics *UpdateChannelMetrics) CountMergeNetworkMapDuration(duration time.Duration) {
	metrics.mergeNetworkMapDurationMicro.Record(metrics.ctx, duration.Microseconds())
}

func (metrics *UpdateChannelMetrics) CountToSyncResponseDuration(duration time.Duration) {
	metrics.toSyncResponseDurationMicro.Record(metrics.ctx, duration.Microseconds())
}

// CountBufferPush counts how many buffer push operations are happening on an empty buffer
func (metrics *UpdateChannelMetrics) CountBufferPush() {
	metrics.bufferPushCounter.Add(metrics.ctx, 1)
}

// CountBufferOverwrite counts how many buffer overwrite operations are happening on a non-empty buffer
func (metrics *UpdateChannelMetrics) CountBufferOverwrite() {
	metrics.bufferOverwriteCounter.Add(metrics.ctx, 1)
}

// CountBufferIgnore counts how many buffer ignore operations are happening when a new update is pushed
func (metrics *UpdateChannelMetrics) CountBufferIgnore() {
	metrics.bufferIgnoreCounter.Add(metrics.ctx, 1)
}
