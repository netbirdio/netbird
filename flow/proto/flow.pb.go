// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v4.24.3
// source: flow.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Flow event types
type Type int32

const (
	Type_TYPE_UNKNOWN Type = 0
	Type_TYPE_START   Type = 1
	Type_TYPE_END     Type = 2
	Type_TYPE_DROP    Type = 3
)

// Enum value maps for Type.
var (
	Type_name = map[int32]string{
		0: "TYPE_UNKNOWN",
		1: "TYPE_START",
		2: "TYPE_END",
		3: "TYPE_DROP",
	}
	Type_value = map[string]int32{
		"TYPE_UNKNOWN": 0,
		"TYPE_START":   1,
		"TYPE_END":     2,
		"TYPE_DROP":    3,
	}
)

func (x Type) Enum() *Type {
	p := new(Type)
	*p = x
	return p
}

func (x Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Type) Descriptor() protoreflect.EnumDescriptor {
	return file_flow_proto_enumTypes[0].Descriptor()
}

func (Type) Type() protoreflect.EnumType {
	return &file_flow_proto_enumTypes[0]
}

func (x Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Type.Descriptor instead.
func (Type) EnumDescriptor() ([]byte, []int) {
	return file_flow_proto_rawDescGZIP(), []int{0}
}

// Flow direction
type Direction int32

const (
	Direction_DIRECTION_UNKNOWN Direction = 0
	Direction_INGRESS           Direction = 1
	Direction_EGRESS            Direction = 2
)

// Enum value maps for Direction.
var (
	Direction_name = map[int32]string{
		0: "DIRECTION_UNKNOWN",
		1: "INGRESS",
		2: "EGRESS",
	}
	Direction_value = map[string]int32{
		"DIRECTION_UNKNOWN": 0,
		"INGRESS":           1,
		"EGRESS":            2,
	}
)

func (x Direction) Enum() *Direction {
	p := new(Direction)
	*p = x
	return p
}

func (x Direction) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Direction) Descriptor() protoreflect.EnumDescriptor {
	return file_flow_proto_enumTypes[1].Descriptor()
}

func (Direction) Type() protoreflect.EnumType {
	return &file_flow_proto_enumTypes[1]
}

func (x Direction) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Direction.Descriptor instead.
func (Direction) EnumDescriptor() ([]byte, []int) {
	return file_flow_proto_rawDescGZIP(), []int{1}
}

type FlowEvent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Unique client event identifier
	EventId string `protobuf:"bytes,1,opt,name=event_id,json=eventId,proto3" json:"event_id,omitempty"`
	// When the event occurred
	Timestamp *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// Public key of the sending peer
	PublicKey  []byte      `protobuf:"bytes,4,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	FlowFields *FlowFields `protobuf:"bytes,5,opt,name=flow_fields,json=flowFields,proto3" json:"flow_fields,omitempty"`
}

func (x *FlowEvent) Reset() {
	*x = FlowEvent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_flow_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FlowEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlowEvent) ProtoMessage() {}

func (x *FlowEvent) ProtoReflect() protoreflect.Message {
	mi := &file_flow_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlowEvent.ProtoReflect.Descriptor instead.
func (*FlowEvent) Descriptor() ([]byte, []int) {
	return file_flow_proto_rawDescGZIP(), []int{0}
}

func (x *FlowEvent) GetEventId() string {
	if x != nil {
		return x.EventId
	}
	return ""
}

func (x *FlowEvent) GetTimestamp() *timestamppb.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

func (x *FlowEvent) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *FlowEvent) GetFlowFields() *FlowFields {
	if x != nil {
		return x.FlowFields
	}
	return nil
}

type FlowEventAck struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Unique client event identifier that has been ack'ed
	EventId string `protobuf:"bytes,1,opt,name=event_id,json=eventId,proto3" json:"event_id,omitempty"`
}

func (x *FlowEventAck) Reset() {
	*x = FlowEventAck{}
	if protoimpl.UnsafeEnabled {
		mi := &file_flow_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FlowEventAck) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlowEventAck) ProtoMessage() {}

func (x *FlowEventAck) ProtoReflect() protoreflect.Message {
	mi := &file_flow_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlowEventAck.ProtoReflect.Descriptor instead.
func (*FlowEventAck) Descriptor() ([]byte, []int) {
	return file_flow_proto_rawDescGZIP(), []int{1}
}

func (x *FlowEventAck) GetEventId() string {
	if x != nil {
		return x.EventId
	}
	return ""
}

type FlowFields struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Unique client flow session identifier
	FlowId []byte `protobuf:"bytes,1,opt,name=flow_id,json=flowId,proto3" json:"flow_id,omitempty"`
	// Flow type
	Type Type `protobuf:"varint,2,opt,name=type,proto3,enum=flow.Type" json:"type,omitempty"`
	// RuleId identifies the rule that allowed or denied the connection
	RuleId []byte `protobuf:"bytes,3,opt,name=rule_id,json=ruleId,proto3" json:"rule_id,omitempty"`
	// Initiating traffic direction
	Direction Direction `protobuf:"varint,4,opt,name=direction,proto3,enum=flow.Direction" json:"direction,omitempty"`
	// IP protocol number
	Protocol uint32 `protobuf:"varint,5,opt,name=protocol,proto3" json:"protocol,omitempty"`
	// Source IP address
	SourceIp []byte `protobuf:"bytes,6,opt,name=source_ip,json=sourceIp,proto3" json:"source_ip,omitempty"`
	// Destination IP address
	DestIp []byte `protobuf:"bytes,7,opt,name=dest_ip,json=destIp,proto3" json:"dest_ip,omitempty"`
	// Layer 4 -specific information
	//
	// Types that are assignable to ConnectionInfo:
	//
	//	*FlowFields_PortInfo
	//	*FlowFields_IcmpInfo
	ConnectionInfo isFlowFields_ConnectionInfo `protobuf_oneof:"connection_info"`
	// Number of packets
	RxPackets uint64 `protobuf:"varint,10,opt,name=rx_packets,json=rxPackets,proto3" json:"rx_packets,omitempty"`
	TxPackets uint64 `protobuf:"varint,11,opt,name=tx_packets,json=txPackets,proto3" json:"tx_packets,omitempty"`
	// Number of bytes
	RxBytes uint64 `protobuf:"varint,12,opt,name=rx_bytes,json=rxBytes,proto3" json:"rx_bytes,omitempty"`
	TxBytes uint64 `protobuf:"varint,13,opt,name=tx_bytes,json=txBytes,proto3" json:"tx_bytes,omitempty"`
}

func (x *FlowFields) Reset() {
	*x = FlowFields{}
	if protoimpl.UnsafeEnabled {
		mi := &file_flow_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FlowFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlowFields) ProtoMessage() {}

func (x *FlowFields) ProtoReflect() protoreflect.Message {
	mi := &file_flow_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlowFields.ProtoReflect.Descriptor instead.
func (*FlowFields) Descriptor() ([]byte, []int) {
	return file_flow_proto_rawDescGZIP(), []int{2}
}

func (x *FlowFields) GetFlowId() []byte {
	if x != nil {
		return x.FlowId
	}
	return nil
}

func (x *FlowFields) GetType() Type {
	if x != nil {
		return x.Type
	}
	return Type_TYPE_UNKNOWN
}

func (x *FlowFields) GetRuleId() []byte {
	if x != nil {
		return x.RuleId
	}
	return nil
}

func (x *FlowFields) GetDirection() Direction {
	if x != nil {
		return x.Direction
	}
	return Direction_DIRECTION_UNKNOWN
}

func (x *FlowFields) GetProtocol() uint32 {
	if x != nil {
		return x.Protocol
	}
	return 0
}

func (x *FlowFields) GetSourceIp() []byte {
	if x != nil {
		return x.SourceIp
	}
	return nil
}

func (x *FlowFields) GetDestIp() []byte {
	if x != nil {
		return x.DestIp
	}
	return nil
}

func (m *FlowFields) GetConnectionInfo() isFlowFields_ConnectionInfo {
	if m != nil {
		return m.ConnectionInfo
	}
	return nil
}

func (x *FlowFields) GetPortInfo() *PortInfo {
	if x, ok := x.GetConnectionInfo().(*FlowFields_PortInfo); ok {
		return x.PortInfo
	}
	return nil
}

func (x *FlowFields) GetIcmpInfo() *ICMPInfo {
	if x, ok := x.GetConnectionInfo().(*FlowFields_IcmpInfo); ok {
		return x.IcmpInfo
	}
	return nil
}

func (x *FlowFields) GetRxPackets() uint64 {
	if x != nil {
		return x.RxPackets
	}
	return 0
}

func (x *FlowFields) GetTxPackets() uint64 {
	if x != nil {
		return x.TxPackets
	}
	return 0
}

func (x *FlowFields) GetRxBytes() uint64 {
	if x != nil {
		return x.RxBytes
	}
	return 0
}

func (x *FlowFields) GetTxBytes() uint64 {
	if x != nil {
		return x.TxBytes
	}
	return 0
}

type isFlowFields_ConnectionInfo interface {
	isFlowFields_ConnectionInfo()
}

type FlowFields_PortInfo struct {
	// TCP/UDP port information
	PortInfo *PortInfo `protobuf:"bytes,8,opt,name=port_info,json=portInfo,proto3,oneof"`
}

type FlowFields_IcmpInfo struct {
	// ICMP type and code
	IcmpInfo *ICMPInfo `protobuf:"bytes,9,opt,name=icmp_info,json=icmpInfo,proto3,oneof"`
}

func (*FlowFields_PortInfo) isFlowFields_ConnectionInfo() {}

func (*FlowFields_IcmpInfo) isFlowFields_ConnectionInfo() {}

// TCP/UDP port information
type PortInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SourcePort uint32 `protobuf:"varint,1,opt,name=source_port,json=sourcePort,proto3" json:"source_port,omitempty"`
	DestPort   uint32 `protobuf:"varint,2,opt,name=dest_port,json=destPort,proto3" json:"dest_port,omitempty"`
}

func (x *PortInfo) Reset() {
	*x = PortInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_flow_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PortInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PortInfo) ProtoMessage() {}

func (x *PortInfo) ProtoReflect() protoreflect.Message {
	mi := &file_flow_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PortInfo.ProtoReflect.Descriptor instead.
func (*PortInfo) Descriptor() ([]byte, []int) {
	return file_flow_proto_rawDescGZIP(), []int{3}
}

func (x *PortInfo) GetSourcePort() uint32 {
	if x != nil {
		return x.SourcePort
	}
	return 0
}

func (x *PortInfo) GetDestPort() uint32 {
	if x != nil {
		return x.DestPort
	}
	return 0
}

// ICMP message information
type ICMPInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IcmpType uint32 `protobuf:"varint,1,opt,name=icmp_type,json=icmpType,proto3" json:"icmp_type,omitempty"`
	IcmpCode uint32 `protobuf:"varint,2,opt,name=icmp_code,json=icmpCode,proto3" json:"icmp_code,omitempty"`
}

func (x *ICMPInfo) Reset() {
	*x = ICMPInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_flow_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ICMPInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ICMPInfo) ProtoMessage() {}

func (x *ICMPInfo) ProtoReflect() protoreflect.Message {
	mi := &file_flow_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ICMPInfo.ProtoReflect.Descriptor instead.
func (*ICMPInfo) Descriptor() ([]byte, []int) {
	return file_flow_proto_rawDescGZIP(), []int{4}
}

func (x *ICMPInfo) GetIcmpType() uint32 {
	if x != nil {
		return x.IcmpType
	}
	return 0
}

func (x *ICMPInfo) GetIcmpCode() uint32 {
	if x != nil {
		return x.IcmpCode
	}
	return 0
}

var File_flow_proto protoreflect.FileDescriptor

var file_flow_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x66, 0x6c,
	0x6f, 0x77, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xb2, 0x01, 0x0a, 0x09, 0x46, 0x6c, 0x6f, 0x77, 0x45, 0x76, 0x65, 0x6e,
	0x74, 0x12, 0x19, 0x0a, 0x08, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x38, 0x0a, 0x09,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x5f, 0x6b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x31, 0x0a, 0x0b, 0x66, 0x6c, 0x6f, 0x77, 0x5f, 0x66, 0x69,
	0x65, 0x6c, 0x64, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x66, 0x6c, 0x6f,
	0x77, 0x2e, 0x46, 0x6c, 0x6f, 0x77, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x52, 0x0a, 0x66, 0x6c,
	0x6f, 0x77, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x22, 0x29, 0x0a, 0x0c, 0x46, 0x6c, 0x6f, 0x77,
	0x45, 0x76, 0x65, 0x6e, 0x74, 0x41, 0x63, 0x6b, 0x12, 0x19, 0x0a, 0x08, 0x65, 0x76, 0x65, 0x6e,
	0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x65, 0x76, 0x65, 0x6e,
	0x74, 0x49, 0x64, 0x22, 0xc4, 0x03, 0x0a, 0x0a, 0x46, 0x6c, 0x6f, 0x77, 0x46, 0x69, 0x65, 0x6c,
	0x64, 0x73, 0x12, 0x17, 0x0a, 0x07, 0x66, 0x6c, 0x6f, 0x77, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x06, 0x66, 0x6c, 0x6f, 0x77, 0x49, 0x64, 0x12, 0x1e, 0x0a, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0a, 0x2e, 0x66, 0x6c, 0x6f, 0x77,
	0x2e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x72,
	0x75, 0x6c, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x72, 0x75,
	0x6c, 0x65, 0x49, 0x64, 0x12, 0x2d, 0x0a, 0x09, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0f, 0x2e, 0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x44,
	0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x09, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12,
	0x1b, 0x0a, 0x09, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69, 0x70, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x08, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x70, 0x12, 0x17, 0x0a, 0x07,
	0x64, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x70, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x64,
	0x65, 0x73, 0x74, 0x49, 0x70, 0x12, 0x2d, 0x0a, 0x09, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x69, 0x6e,
	0x66, 0x6f, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x66, 0x6c, 0x6f, 0x77, 0x2e,
	0x50, 0x6f, 0x72, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x48, 0x00, 0x52, 0x08, 0x70, 0x6f, 0x72, 0x74,
	0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2d, 0x0a, 0x09, 0x69, 0x63, 0x6d, 0x70, 0x5f, 0x69, 0x6e, 0x66,
	0x6f, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x49,
	0x43, 0x4d, 0x50, 0x49, 0x6e, 0x66, 0x6f, 0x48, 0x00, 0x52, 0x08, 0x69, 0x63, 0x6d, 0x70, 0x49,
	0x6e, 0x66, 0x6f, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x78, 0x5f, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74,
	0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x72, 0x78, 0x50, 0x61, 0x63, 0x6b, 0x65,
	0x74, 0x73, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x78, 0x5f, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73,
	0x18, 0x0b, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x74, 0x78, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74,
	0x73, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x78, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x0c, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x07, 0x72, 0x78, 0x42, 0x79, 0x74, 0x65, 0x73, 0x12, 0x19, 0x0a, 0x08,
	0x74, 0x78, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07,
	0x74, 0x78, 0x42, 0x79, 0x74, 0x65, 0x73, 0x42, 0x11, 0x0a, 0x0f, 0x63, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x22, 0x48, 0x0a, 0x08, 0x50, 0x6f,
	0x72, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x1b, 0x0a, 0x09, 0x64, 0x65, 0x73, 0x74, 0x5f,
	0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x64, 0x65, 0x73, 0x74,
	0x50, 0x6f, 0x72, 0x74, 0x22, 0x44, 0x0a, 0x08, 0x49, 0x43, 0x4d, 0x50, 0x49, 0x6e, 0x66, 0x6f,
	0x12, 0x1b, 0x0a, 0x09, 0x69, 0x63, 0x6d, 0x70, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x08, 0x69, 0x63, 0x6d, 0x70, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1b, 0x0a,
	0x09, 0x69, 0x63, 0x6d, 0x70, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x08, 0x69, 0x63, 0x6d, 0x70, 0x43, 0x6f, 0x64, 0x65, 0x2a, 0x45, 0x0a, 0x04, 0x54, 0x79,
	0x70, 0x65, 0x12, 0x10, 0x0a, 0x0c, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x4b, 0x4e, 0x4f,
	0x57, 0x4e, 0x10, 0x00, 0x12, 0x0e, 0x0a, 0x0a, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x53, 0x54, 0x41,
	0x52, 0x54, 0x10, 0x01, 0x12, 0x0c, 0x0a, 0x08, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x45, 0x4e, 0x44,
	0x10, 0x02, 0x12, 0x0d, 0x0a, 0x09, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x44, 0x52, 0x4f, 0x50, 0x10,
	0x03, 0x2a, 0x3b, 0x0a, 0x09, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x15,
	0x0a, 0x11, 0x44, 0x49, 0x52, 0x45, 0x43, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x55, 0x4e, 0x4b, 0x4e,
	0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x49, 0x4e, 0x47, 0x52, 0x45, 0x53, 0x53,
	0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x45, 0x47, 0x52, 0x45, 0x53, 0x53, 0x10, 0x02, 0x32, 0x42,
	0x0a, 0x0b, 0x46, 0x6c, 0x6f, 0x77, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x33, 0x0a,
	0x06, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x0f, 0x2e, 0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x46,
	0x6c, 0x6f, 0x77, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x1a, 0x12, 0x2e, 0x66, 0x6c, 0x6f, 0x77, 0x2e,
	0x46, 0x6c, 0x6f, 0x77, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x41, 0x63, 0x6b, 0x22, 0x00, 0x28, 0x01,
	0x30, 0x01, 0x42, 0x08, 0x5a, 0x06, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_flow_proto_rawDescOnce sync.Once
	file_flow_proto_rawDescData = file_flow_proto_rawDesc
)

func file_flow_proto_rawDescGZIP() []byte {
	file_flow_proto_rawDescOnce.Do(func() {
		file_flow_proto_rawDescData = protoimpl.X.CompressGZIP(file_flow_proto_rawDescData)
	})
	return file_flow_proto_rawDescData
}

var file_flow_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_flow_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_flow_proto_goTypes = []interface{}{
	(Type)(0),                     // 0: flow.Type
	(Direction)(0),                // 1: flow.Direction
	(*FlowEvent)(nil),             // 2: flow.FlowEvent
	(*FlowEventAck)(nil),          // 3: flow.FlowEventAck
	(*FlowFields)(nil),            // 4: flow.FlowFields
	(*PortInfo)(nil),              // 5: flow.PortInfo
	(*ICMPInfo)(nil),              // 6: flow.ICMPInfo
	(*timestamppb.Timestamp)(nil), // 7: google.protobuf.Timestamp
}
var file_flow_proto_depIdxs = []int32{
	7, // 0: flow.FlowEvent.timestamp:type_name -> google.protobuf.Timestamp
	4, // 1: flow.FlowEvent.flow_fields:type_name -> flow.FlowFields
	0, // 2: flow.FlowFields.type:type_name -> flow.Type
	1, // 3: flow.FlowFields.direction:type_name -> flow.Direction
	5, // 4: flow.FlowFields.port_info:type_name -> flow.PortInfo
	6, // 5: flow.FlowFields.icmp_info:type_name -> flow.ICMPInfo
	2, // 6: flow.FlowService.Events:input_type -> flow.FlowEvent
	3, // 7: flow.FlowService.Events:output_type -> flow.FlowEventAck
	7, // [7:8] is the sub-list for method output_type
	6, // [6:7] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_flow_proto_init() }
func file_flow_proto_init() {
	if File_flow_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_flow_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FlowEvent); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_flow_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FlowEventAck); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_flow_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FlowFields); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_flow_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PortInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_flow_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ICMPInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_flow_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*FlowFields_PortInfo)(nil),
		(*FlowFields_IcmpInfo)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_flow_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_flow_proto_goTypes,
		DependencyIndexes: file_flow_proto_depIdxs,
		EnumInfos:         file_flow_proto_enumTypes,
		MessageInfos:      file_flow_proto_msgTypes,
	}.Build()
	File_flow_proto = out.File
	file_flow_proto_rawDesc = nil
	file_flow_proto_goTypes = nil
	file_flow_proto_depIdxs = nil
}
