// Code generated by protoc-gen-go. DO NOT EDIT.
// source: grpc.proto

/*
Package localserver is a generated protocol buffer package.

Web exposes a backend server over gRPC.

It is generated from these files:
	grpc.proto

It has these top-level messages:
	Key
	Value
	KV
	OpResult
*/
package localserver

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Key struct {
	Key string `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
}

func (m *Key) Reset()                    { *m = Key{} }
func (m *Key) String() string            { return proto.CompactTextString(m) }
func (*Key) ProtoMessage()               {}
func (*Key) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Key) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

type Value struct {
	Value string `protobuf:"bytes,1,opt,name=value" json:"value,omitempty"`
}

func (m *Value) Reset()                    { *m = Value{} }
func (m *Value) String() string            { return proto.CompactTextString(m) }
func (*Value) ProtoMessage()               {}
func (*Value) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Value) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

type KV struct {
	Key   string `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
}

func (m *KV) Reset()                    { *m = KV{} }
func (m *KV) String() string            { return proto.CompactTextString(m) }
func (*KV) ProtoMessage()               {}
func (*KV) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *KV) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *KV) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

type OpResult struct {
	ErrCode int64 `protobuf:"varint,1,opt,name=err_code,json=errCode" json:"err_code,omitempty"`
}

func (m *OpResult) Reset()                    { *m = OpResult{} }
func (m *OpResult) String() string            { return proto.CompactTextString(m) }
func (*OpResult) ProtoMessage()               {}
func (*OpResult) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *OpResult) GetErrCode() int64 {
	if m != nil {
		return m.ErrCode
	}
	return 0
}

func init() {
	proto.RegisterType((*Key)(nil), "localserver.Key")
	proto.RegisterType((*Value)(nil), "localserver.Value")
	proto.RegisterType((*KV)(nil), "localserver.KV")
	proto.RegisterType((*OpResult)(nil), "localserver.OpResult")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for GRPC service

type GRPCClient interface {
	Get(ctx context.Context, in *Key, opts ...grpc.CallOption) (*Value, error)
	PutKVStream(ctx context.Context, opts ...grpc.CallOption) (GRPC_PutKVStreamClient, error)
	GetKVStream(ctx context.Context, in *Key, opts ...grpc.CallOption) (GRPC_GetKVStreamClient, error)
}

type gRPCClient struct {
	cc *grpc.ClientConn
}

func NewGRPCClient(cc *grpc.ClientConn) GRPCClient {
	return &gRPCClient{cc}
}

func (c *gRPCClient) Get(ctx context.Context, in *Key, opts ...grpc.CallOption) (*Value, error) {
	out := new(Value)
	err := grpc.Invoke(ctx, "/localserver.GRPC/Get", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gRPCClient) PutKVStream(ctx context.Context, opts ...grpc.CallOption) (GRPC_PutKVStreamClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_GRPC_serviceDesc.Streams[0], c.cc, "/localserver.GRPC/PutKVStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &gRPCPutKVStreamClient{stream}
	return x, nil
}

type GRPC_PutKVStreamClient interface {
	Send(*KV) error
	CloseAndRecv() (*OpResult, error)
	grpc.ClientStream
}

type gRPCPutKVStreamClient struct {
	grpc.ClientStream
}

func (x *gRPCPutKVStreamClient) Send(m *KV) error {
	return x.ClientStream.SendMsg(m)
}

func (x *gRPCPutKVStreamClient) CloseAndRecv() (*OpResult, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(OpResult)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *gRPCClient) GetKVStream(ctx context.Context, in *Key, opts ...grpc.CallOption) (GRPC_GetKVStreamClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_GRPC_serviceDesc.Streams[1], c.cc, "/localserver.GRPC/GetKVStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &gRPCGetKVStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type GRPC_GetKVStreamClient interface {
	Recv() (*KV, error)
	grpc.ClientStream
}

type gRPCGetKVStreamClient struct {
	grpc.ClientStream
}

func (x *gRPCGetKVStreamClient) Recv() (*KV, error) {
	m := new(KV)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for GRPC service

type GRPCServer interface {
	Get(context.Context, *Key) (*Value, error)
	PutKVStream(GRPC_PutKVStreamServer) error
	GetKVStream(*Key, GRPC_GetKVStreamServer) error
}

func RegisterGRPCServer(s *grpc.Server, srv GRPCServer) {
	s.RegisterService(&_GRPC_serviceDesc, srv)
}

func _GRPC_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Key)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GRPCServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/localserver.GRPC/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GRPCServer).Get(ctx, req.(*Key))
	}
	return interceptor(ctx, in, info, handler)
}

func _GRPC_PutKVStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(GRPCServer).PutKVStream(&gRPCPutKVStreamServer{stream})
}

type GRPC_PutKVStreamServer interface {
	SendAndClose(*OpResult) error
	Recv() (*KV, error)
	grpc.ServerStream
}

type gRPCPutKVStreamServer struct {
	grpc.ServerStream
}

func (x *gRPCPutKVStreamServer) SendAndClose(m *OpResult) error {
	return x.ServerStream.SendMsg(m)
}

func (x *gRPCPutKVStreamServer) Recv() (*KV, error) {
	m := new(KV)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _GRPC_GetKVStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Key)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(GRPCServer).GetKVStream(m, &gRPCGetKVStreamServer{stream})
}

type GRPC_GetKVStreamServer interface {
	Send(*KV) error
	grpc.ServerStream
}

type gRPCGetKVStreamServer struct {
	grpc.ServerStream
}

func (x *gRPCGetKVStreamServer) Send(m *KV) error {
	return x.ServerStream.SendMsg(m)
}

var _GRPC_serviceDesc = grpc.ServiceDesc{
	ServiceName: "localserver.GRPC",
	HandlerType: (*GRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Get",
			Handler:    _GRPC_Get_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "PutKVStream",
			Handler:       _GRPC_PutKVStream_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "GetKVStream",
			Handler:       _GRPC_GetKVStream_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "grpc.proto",
}

func init() { proto.RegisterFile("grpc.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 258 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x64, 0x90, 0x41, 0x4b, 0xc3, 0x40,
	0x14, 0x84, 0xb3, 0x8d, 0xd5, 0xfa, 0x72, 0xb0, 0x3c, 0x14, 0xb5, 0x20, 0xc8, 0x82, 0x58, 0x41,
	0x53, 0x51, 0x2f, 0x5e, 0xed, 0x21, 0x87, 0x1c, 0x2c, 0x11, 0x72, 0xf0, 0x22, 0xdb, 0xe4, 0x51,
	0x8b, 0x49, 0x36, 0xbc, 0xec, 0x16, 0xf3, 0x87, 0xfc, 0x9d, 0xd2, 0x56, 0x69, 0xd2, 0xde, 0x66,
	0x67, 0xe7, 0x9b, 0x1d, 0x16, 0x60, 0xc6, 0x65, 0xe2, 0x97, 0xac, 0x8d, 0x46, 0x2f, 0xd3, 0x89,
	0xca, 0x2a, 0xe2, 0x05, 0xb1, 0x3c, 0x05, 0x37, 0xa4, 0x1a, 0xfb, 0xe0, 0x7e, 0x51, 0x7d, 0x26,
	0x2e, 0xc5, 0xf0, 0x30, 0x5a, 0x4a, 0x79, 0x01, 0xdd, 0x58, 0x65, 0x96, 0xf0, 0x18, 0xba, 0x8b,
	0xa5, 0xf8, 0xbb, 0x5c, 0x1f, 0xe4, 0x2d, 0x74, 0xc2, 0x78, 0x17, 0xdb, 0xa4, 0x3b, 0xcd, 0xf4,
	0x15, 0xf4, 0x5e, 0xcb, 0x88, 0x2a, 0x9b, 0x19, 0x3c, 0x87, 0x1e, 0x31, 0x7f, 0x24, 0x3a, 0x5d,
	0x57, 0xba, 0xd1, 0x01, 0x31, 0x8f, 0x75, 0x4a, 0x0f, 0x3f, 0x02, 0xf6, 0x82, 0x68, 0x32, 0xc6,
	0x3b, 0x70, 0x03, 0x32, 0xd8, 0xf7, 0x1b, 0x53, 0xfd, 0x90, 0xea, 0x01, 0xb6, 0x9c, 0xd5, 0x40,
	0xe9, 0xe0, 0x33, 0x78, 0x13, 0x6b, 0xc2, 0xf8, 0xcd, 0x30, 0xa9, 0x1c, 0x8f, 0xda, 0x58, 0x3c,
	0x38, 0x69, 0x19, 0xff, 0x4b, 0xa4, 0x33, 0x14, 0xf8, 0x04, 0x5e, 0x40, 0x1b, 0x74, 0xf7, 0xc5,
	0xed, 0x32, 0xe9, 0xdc, 0x8b, 0x97, 0x9b, 0xf7, 0xeb, 0xd9, 0xdc, 0x7c, 0xda, 0xa9, 0x9f, 0xe8,
	0x7c, 0xa4, 0x8a, 0xef, 0xb9, 0xb6, 0x55, 0xae, 0x53, 0xe2, 0x22, 0x57, 0xc5, 0xa8, 0x41, 0x4c,
	0xf7, 0x57, 0x9f, 0xfe, 0xf8, 0x1b, 0x00, 0x00, 0xff, 0xff, 0x77, 0xe5, 0xc8, 0x8f, 0x82, 0x01,
	0x00, 0x00,
}