package wgbackend

import "github.com/netbirdio/wireguard-go/conn"

type (
	BatchReader    = conn.BatchReader
	Bind           = conn.Bind
	Endpoint       = conn.Endpoint
	ReceiveFunc    = conn.ReceiveFunc
	StdNetBind     = conn.StdNetBind
	StdNetEndpoint = conn.StdNetEndpoint
)

const (
	IdealBatchSize         = conn.IdealBatchSize
	UdpSegmentMaxDatagrams = conn.UdpSegmentMaxDatagrams
)

var (
	ControlFns                       = conn.ControlFns
	GetGSOSize                       = conn.GetGSOSize
	GetSrcFromControl                = conn.GetSrcFromControl
	NewDefaultBind                   = conn.NewDefaultBind
	NewStdNetBind                    = conn.NewStdNetBind
	NewStdNetBindWithReceiverCreator = conn.NewStdNetBindWithReceiverCreator
	SplitCoalescedMessages           = conn.SplitCoalescedMessages
)
