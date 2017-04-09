// Code generated by protoc-gen-go.
// source: server-config.proto
// DO NOT EDIT!

/*
Package pb is a generated protocol buffer package.

It is generated from these files:
	server-config.proto

It has these top-level messages:
	ServerConfig
*/
package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type ServerConfig struct {
	ServerCertPath               string `protobuf:"bytes,1,opt,name=server_cert_path,json=serverCertPath" json:"server_cert_path,omitempty"`
	ServerKeyPath                string `protobuf:"bytes,2,opt,name=server_key_path,json=serverKeyPath" json:"server_key_path,omitempty"`
	ListenBind                   string `protobuf:"bytes,3,opt,name=listen_bind,json=listenBind" json:"listen_bind,omitempty"`
	InsecureHttpServerForTesting bool   `protobuf:"varint,4,opt,name=insecure_http_server_for_testing,json=insecureHttpServerForTesting" json:"insecure_http_server_for_testing,omitempty"`
}

func (m *ServerConfig) Reset()                    { *m = ServerConfig{} }
func (m *ServerConfig) String() string            { return proto.CompactTextString(m) }
func (*ServerConfig) ProtoMessage()               {}
func (*ServerConfig) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *ServerConfig) GetServerCertPath() string {
	if m != nil {
		return m.ServerCertPath
	}
	return ""
}

func (m *ServerConfig) GetServerKeyPath() string {
	if m != nil {
		return m.ServerKeyPath
	}
	return ""
}

func (m *ServerConfig) GetListenBind() string {
	if m != nil {
		return m.ListenBind
	}
	return ""
}

func (m *ServerConfig) GetInsecureHttpServerForTesting() bool {
	if m != nil {
		return m.InsecureHttpServerForTesting
	}
	return false
}

func init() {
	proto.RegisterType((*ServerConfig)(nil), "continusec.vds.ServerConfig")
}

func init() { proto.RegisterFile("server-config.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 210 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x34, 0xcf, 0xc1, 0x4a, 0xc4, 0x30,
	0x10, 0x80, 0x61, 0xb2, 0x2e, 0xa2, 0x51, 0x57, 0x89, 0x97, 0x1e, 0x04, 0x8b, 0x07, 0xe9, 0xc5,
	0xbd, 0xf8, 0x06, 0x2d, 0x14, 0xc1, 0x8b, 0x54, 0x4f, 0x5e, 0x42, 0x9b, 0x4e, 0xdb, 0xa0, 0x4c,
	0xc2, 0x64, 0x5a, 0xe8, 0x23, 0xfa, 0x56, 0x42, 0xd2, 0xbd, 0xfe, 0x7c, 0x33, 0xcc, 0xc8, 0xfb,
	0x00, 0xb4, 0x00, 0xbd, 0x18, 0x87, 0x83, 0x1d, 0x8f, 0x9e, 0x1c, 0x3b, 0x75, 0x30, 0x0e, 0xd9,
	0xe2, 0x1c, 0xc0, 0x1c, 0x97, 0x3e, 0x3c, 0xfd, 0x09, 0x79, 0xfd, 0x19, 0x5d, 0x15, 0x99, 0x2a,
	0xe4, 0x5d, 0x9a, 0xd3, 0x06, 0x88, 0xb5, 0x6f, 0x79, 0xca, 0x44, 0x2e, 0x8a, 0xcb, 0xe6, 0x90,
	0x7a, 0x05, 0xc4, 0x1f, 0x2d, 0x4f, 0xea, 0x59, 0xde, 0x6e, 0xf2, 0x07, 0xd6, 0x04, 0x77, 0x11,
	0xde, 0xa4, 0xfc, 0x0e, 0x6b, 0x74, 0x8f, 0xf2, 0xea, 0xd7, 0x06, 0x06, 0xd4, 0x9d, 0xc5, 0x3e,
	0x3b, 0x8b, 0x46, 0xa6, 0x54, 0x5a, 0xec, 0x55, 0x2d, 0x73, 0x8b, 0x01, 0xcc, 0x4c, 0xa0, 0x27,
	0x66, 0xaf, 0xb7, 0xb5, 0x83, 0x23, 0xcd, 0x10, 0xd8, 0xe2, 0x98, 0xed, 0x73, 0x51, 0x5c, 0x34,
	0x0f, 0x27, 0xf7, 0xc6, 0xec, 0xd3, 0xd9, 0xb5, 0xa3, 0xaf, 0x64, 0xca, 0xfd, 0xf7, 0xce, 0x77,
	0xdd, 0x79, 0x7c, 0xf4, 0xf5, 0x3f, 0x00, 0x00, 0xff, 0xff, 0x15, 0xcb, 0xea, 0xbe, 0xff, 0x00,
	0x00, 0x00,
}