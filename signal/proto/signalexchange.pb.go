// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        (unknown)
// source: signalexchange/signalexchange.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/descriptorpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Message type
type Body_Type int32

const (
	Body_OFFER     Body_Type = 0
	Body_ANSWER    Body_Type = 1
	Body_CANDIDATE Body_Type = 2
	Body_MODE      Body_Type = 4
)

// Enum value maps for Body_Type.
var (
	Body_Type_name = map[int32]string{
		0: "OFFER",
		1: "ANSWER",
		2: "CANDIDATE",
		4: "MODE",
	}
	Body_Type_value = map[string]int32{
		"OFFER":     0,
		"ANSWER":    1,
		"CANDIDATE": 2,
		"MODE":      4,
	}
)

func (x Body_Type) Enum() *Body_Type {
	p := new(Body_Type)
	*p = x
	return p
}

func (x Body_Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Body_Type) Descriptor() protoreflect.EnumDescriptor {
	return file_signalexchange_signalexchange_proto_enumTypes[0].Descriptor()
}

func (Body_Type) Type() protoreflect.EnumType {
	return &file_signalexchange_signalexchange_proto_enumTypes[0]
}

func (x Body_Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Body_Type.Descriptor instead.
func (Body_Type) EnumDescriptor() ([]byte, []int) {
	return file_signalexchange_signalexchange_proto_rawDescGZIP(), []int{2, 0}
}

// Used for sending through signal.
// The body of this message is the Body message encrypted with the Wireguard private key and the remote Peer key
type EncryptedMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Wireguard public key
	Key string `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	// Wireguard public key of the remote peer to connect to
	RemoteKey string `protobuf:"bytes,3,opt,name=remoteKey,proto3" json:"remoteKey,omitempty"`
	// encrypted message Body
	Body []byte `protobuf:"bytes,4,opt,name=body,proto3" json:"body,omitempty"`
}

func (x *EncryptedMessage) Reset() {
	*x = EncryptedMessage{}
	mi := &file_signalexchange_signalexchange_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EncryptedMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptedMessage) ProtoMessage() {}

func (x *EncryptedMessage) ProtoReflect() protoreflect.Message {
	mi := &file_signalexchange_signalexchange_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptedMessage.ProtoReflect.Descriptor instead.
func (*EncryptedMessage) Descriptor() ([]byte, []int) {
	return file_signalexchange_signalexchange_proto_rawDescGZIP(), []int{0}
}

func (x *EncryptedMessage) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *EncryptedMessage) GetRemoteKey() string {
	if x != nil {
		return x.RemoteKey
	}
	return ""
}

func (x *EncryptedMessage) GetBody() []byte {
	if x != nil {
		return x.Body
	}
	return nil
}

// A decrypted representation of the EncryptedMessage. Used locally before/after encryption
type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// WireGuard public key
	Key string `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	// WireGuard public key of the remote peer to connect to
	RemoteKey string `protobuf:"bytes,3,opt,name=remoteKey,proto3" json:"remoteKey,omitempty"`
	Body      *Body  `protobuf:"bytes,4,opt,name=body,proto3" json:"body,omitempty"`
}

func (x *Message) Reset() {
	*x = Message{}
	mi := &file_signalexchange_signalexchange_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_signalexchange_signalexchange_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_signalexchange_signalexchange_proto_rawDescGZIP(), []int{1}
}

func (x *Message) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Message) GetRemoteKey() string {
	if x != nil {
		return x.RemoteKey
	}
	return ""
}

func (x *Message) GetBody() *Body {
	if x != nil {
		return x.Body
	}
	return nil
}

// Actual body of the message that can contain credentials (type OFFER/ANSWER) or connection Candidate
// This part will be encrypted
type Body struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type    Body_Type `protobuf:"varint,1,opt,name=type,proto3,enum=signalexchange.Body_Type" json:"type,omitempty"`
	Payload string    `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`
	// wgListenPort is an actual WireGuard listen port
	WgListenPort   uint32 `protobuf:"varint,3,opt,name=wgListenPort,proto3" json:"wgListenPort,omitempty"`
	NetBirdVersion string `protobuf:"bytes,4,opt,name=netBirdVersion,proto3" json:"netBirdVersion,omitempty"`
	Mode           *Mode  `protobuf:"bytes,5,opt,name=mode,proto3" json:"mode,omitempty"`
	// featuresSupported list of supported features by the client of this protocol
	FeaturesSupported []uint32 `protobuf:"varint,6,rep,packed,name=featuresSupported,proto3" json:"featuresSupported,omitempty"`
	// RosenpassConfig is a Rosenpass config of the remote peer our peer tries to connect to
	RosenpassConfig *RosenpassConfig `protobuf:"bytes,7,opt,name=rosenpassConfig,proto3" json:"rosenpassConfig,omitempty"`
	// relayServerAddress is url of the relay server
	RelayServerAddress string `protobuf:"bytes,8,opt,name=relayServerAddress,proto3" json:"relayServerAddress,omitempty"`
}

func (x *Body) Reset() {
	*x = Body{}
	mi := &file_signalexchange_signalexchange_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Body) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Body) ProtoMessage() {}

func (x *Body) ProtoReflect() protoreflect.Message {
	mi := &file_signalexchange_signalexchange_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Body.ProtoReflect.Descriptor instead.
func (*Body) Descriptor() ([]byte, []int) {
	return file_signalexchange_signalexchange_proto_rawDescGZIP(), []int{2}
}

func (x *Body) GetType() Body_Type {
	if x != nil {
		return x.Type
	}
	return Body_OFFER
}

func (x *Body) GetPayload() string {
	if x != nil {
		return x.Payload
	}
	return ""
}

func (x *Body) GetWgListenPort() uint32 {
	if x != nil {
		return x.WgListenPort
	}
	return 0
}

func (x *Body) GetNetBirdVersion() string {
	if x != nil {
		return x.NetBirdVersion
	}
	return ""
}

func (x *Body) GetMode() *Mode {
	if x != nil {
		return x.Mode
	}
	return nil
}

func (x *Body) GetFeaturesSupported() []uint32 {
	if x != nil {
		return x.FeaturesSupported
	}
	return nil
}

func (x *Body) GetRosenpassConfig() *RosenpassConfig {
	if x != nil {
		return x.RosenpassConfig
	}
	return nil
}

func (x *Body) GetRelayServerAddress() string {
	if x != nil {
		return x.RelayServerAddress
	}
	return ""
}

// Mode indicates a connection mode
type Mode struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Direct *bool `protobuf:"varint,1,opt,name=direct,proto3,oneof" json:"direct,omitempty"`
}

func (x *Mode) Reset() {
	*x = Mode{}
	mi := &file_signalexchange_signalexchange_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Mode) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Mode) ProtoMessage() {}

func (x *Mode) ProtoReflect() protoreflect.Message {
	mi := &file_signalexchange_signalexchange_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Mode.ProtoReflect.Descriptor instead.
func (*Mode) Descriptor() ([]byte, []int) {
	return file_signalexchange_signalexchange_proto_rawDescGZIP(), []int{3}
}

func (x *Mode) GetDirect() bool {
	if x != nil && x.Direct != nil {
		return *x.Direct
	}
	return false
}

type RosenpassConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RosenpassPubKey []byte `protobuf:"bytes,1,opt,name=rosenpassPubKey,proto3" json:"rosenpassPubKey,omitempty"`
	// rosenpassServerAddr is an IP:port of the rosenpass service
	RosenpassServerAddr string `protobuf:"bytes,2,opt,name=rosenpassServerAddr,proto3" json:"rosenpassServerAddr,omitempty"`
}

func (x *RosenpassConfig) Reset() {
	*x = RosenpassConfig{}
	mi := &file_signalexchange_signalexchange_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RosenpassConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RosenpassConfig) ProtoMessage() {}

func (x *RosenpassConfig) ProtoReflect() protoreflect.Message {
	mi := &file_signalexchange_signalexchange_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RosenpassConfig.ProtoReflect.Descriptor instead.
func (*RosenpassConfig) Descriptor() ([]byte, []int) {
	return file_signalexchange_signalexchange_proto_rawDescGZIP(), []int{4}
}

func (x *RosenpassConfig) GetRosenpassPubKey() []byte {
	if x != nil {
		return x.RosenpassPubKey
	}
	return nil
}

func (x *RosenpassConfig) GetRosenpassServerAddr() string {
	if x != nil {
		return x.RosenpassServerAddr
	}
	return ""
}

var File_signalexchange_signalexchange_proto protoreflect.FileDescriptor

var file_signalexchange_signalexchange_proto_rawDesc = []byte{
	0x0a, 0x23, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65,
	0x2f, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x65, 0x78, 0x63,
	0x68, 0x61, 0x6e, 0x67, 0x65, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f,
	0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x56, 0x0a, 0x10, 0x45, 0x6e, 0x63, 0x72, 0x79,
	0x70, 0x74, 0x65, 0x64, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x1c, 0x0a,
	0x09, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x62,
	0x6f, 0x64, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x22,
	0x63, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65,
	0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x1c, 0x0a, 0x09,
	0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x28, 0x0a, 0x04, 0x62, 0x6f,
	0x64, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61,
	0x6c, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x2e, 0x42, 0x6f, 0x64, 0x79, 0x52, 0x04,
	0x62, 0x6f, 0x64, 0x79, 0x22, 0xa6, 0x03, 0x0a, 0x04, 0x42, 0x6f, 0x64, 0x79, 0x12, 0x2d, 0x0a,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x19, 0x2e, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x6c, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x2e, 0x42, 0x6f, 0x64,
	0x79, 0x2e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x18, 0x0a, 0x07,
	0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x22, 0x0a, 0x0c, 0x77, 0x67, 0x4c, 0x69, 0x73, 0x74,
	0x65, 0x6e, 0x50, 0x6f, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x77, 0x67,
	0x4c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x26, 0x0a, 0x0e, 0x6e, 0x65,
	0x74, 0x42, 0x69, 0x72, 0x64, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0e, 0x6e, 0x65, 0x74, 0x42, 0x69, 0x72, 0x64, 0x56, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x12, 0x28, 0x0a, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x14, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67,
	0x65, 0x2e, 0x4d, 0x6f, 0x64, 0x65, 0x52, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x12, 0x2c, 0x0a, 0x11,
	0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65,
	0x64, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x11, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x73, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x12, 0x49, 0x0a, 0x0f, 0x72, 0x6f,
	0x73, 0x65, 0x6e, 0x70, 0x61, 0x73, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x65, 0x78, 0x63, 0x68,
	0x61, 0x6e, 0x67, 0x65, 0x2e, 0x52, 0x6f, 0x73, 0x65, 0x6e, 0x70, 0x61, 0x73, 0x73, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x52, 0x0f, 0x72, 0x6f, 0x73, 0x65, 0x6e, 0x70, 0x61, 0x73, 0x73, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x2e, 0x0a, 0x12, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x53, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x12, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x41, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x22, 0x36, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x09, 0x0a,
	0x05, 0x4f, 0x46, 0x46, 0x45, 0x52, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x41, 0x4e, 0x53, 0x57,
	0x45, 0x52, 0x10, 0x01, 0x12, 0x0d, 0x0a, 0x09, 0x43, 0x41, 0x4e, 0x44, 0x49, 0x44, 0x41, 0x54,
	0x45, 0x10, 0x02, 0x12, 0x08, 0x0a, 0x04, 0x4d, 0x4f, 0x44, 0x45, 0x10, 0x04, 0x22, 0x2e, 0x0a,
	0x04, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x1b, 0x0a, 0x06, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x08, 0x48, 0x00, 0x52, 0x06, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x88,
	0x01, 0x01, 0x42, 0x09, 0x0a, 0x07, 0x5f, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x22, 0x6d, 0x0a,
	0x0f, 0x52, 0x6f, 0x73, 0x65, 0x6e, 0x70, 0x61, 0x73, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x28, 0x0a, 0x0f, 0x72, 0x6f, 0x73, 0x65, 0x6e, 0x70, 0x61, 0x73, 0x73, 0x50, 0x75, 0x62,
	0x4b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0f, 0x72, 0x6f, 0x73, 0x65, 0x6e,
	0x70, 0x61, 0x73, 0x73, 0x50, 0x75, 0x62, 0x4b, 0x65, 0x79, 0x12, 0x30, 0x0a, 0x13, 0x72, 0x6f,
	0x73, 0x65, 0x6e, 0x70, 0x61, 0x73, 0x73, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x41, 0x64, 0x64,
	0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x72, 0x6f, 0x73, 0x65, 0x6e, 0x70, 0x61,
	0x73, 0x73, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x32, 0xb9, 0x01, 0x0a,
	0x0e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x12,
	0x4c, 0x0a, 0x04, 0x53, 0x65, 0x6e, 0x64, 0x12, 0x20, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c,
	0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x2e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x65, 0x64, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x1a, 0x20, 0x2e, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x6c, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x2e, 0x45, 0x6e, 0x63, 0x72, 0x79,
	0x70, 0x74, 0x65, 0x64, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x00, 0x12, 0x59, 0x0a,
	0x0d, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x12, 0x20,
	0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x2e,
	0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x1a, 0x20, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67,
	0x65, 0x2e, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x22, 0x00, 0x28, 0x01, 0x30, 0x01, 0x42, 0x0e, 0x5a, 0x0c, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x6c, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_signalexchange_signalexchange_proto_rawDescOnce sync.Once
	file_signalexchange_signalexchange_proto_rawDescData = file_signalexchange_signalexchange_proto_rawDesc
)

func file_signalexchange_signalexchange_proto_rawDescGZIP() []byte {
	file_signalexchange_signalexchange_proto_rawDescOnce.Do(func() {
		file_signalexchange_signalexchange_proto_rawDescData = protoimpl.X.CompressGZIP(file_signalexchange_signalexchange_proto_rawDescData)
	})
	return file_signalexchange_signalexchange_proto_rawDescData
}

var file_signalexchange_signalexchange_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_signalexchange_signalexchange_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_signalexchange_signalexchange_proto_goTypes = []any{
	(Body_Type)(0),           // 0: signalexchange.Body.Type
	(*EncryptedMessage)(nil), // 1: signalexchange.EncryptedMessage
	(*Message)(nil),          // 2: signalexchange.Message
	(*Body)(nil),             // 3: signalexchange.Body
	(*Mode)(nil),             // 4: signalexchange.Mode
	(*RosenpassConfig)(nil),  // 5: signalexchange.RosenpassConfig
}
var file_signalexchange_signalexchange_proto_depIdxs = []int32{
	3, // 0: signalexchange.Message.body:type_name -> signalexchange.Body
	0, // 1: signalexchange.Body.type:type_name -> signalexchange.Body.Type
	4, // 2: signalexchange.Body.mode:type_name -> signalexchange.Mode
	5, // 3: signalexchange.Body.rosenpassConfig:type_name -> signalexchange.RosenpassConfig
	1, // 4: signalexchange.SignalExchange.Send:input_type -> signalexchange.EncryptedMessage
	1, // 5: signalexchange.SignalExchange.ConnectStream:input_type -> signalexchange.EncryptedMessage
	1, // 6: signalexchange.SignalExchange.Send:output_type -> signalexchange.EncryptedMessage
	1, // 7: signalexchange.SignalExchange.ConnectStream:output_type -> signalexchange.EncryptedMessage
	6, // [6:8] is the sub-list for method output_type
	4, // [4:6] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_signalexchange_signalexchange_proto_init() }
func file_signalexchange_signalexchange_proto_init() {
	if File_signalexchange_signalexchange_proto != nil {
		return
	}
	file_signalexchange_signalexchange_proto_msgTypes[3].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_signalexchange_signalexchange_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_signalexchange_signalexchange_proto_goTypes,
		DependencyIndexes: file_signalexchange_signalexchange_proto_depIdxs,
		EnumInfos:         file_signalexchange_signalexchange_proto_enumTypes,
		MessageInfos:      file_signalexchange_signalexchange_proto_msgTypes,
	}.Build()
	File_signalexchange_signalexchange_proto = out.File
	file_signalexchange_signalexchange_proto_rawDesc = nil
	file_signalexchange_signalexchange_proto_goTypes = nil
	file_signalexchange_signalexchange_proto_depIdxs = nil
}
