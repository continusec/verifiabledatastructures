// Code generated by protoc-gen-go.
// source: server-config.proto
// DO NOT EDIT!

/*
Package pb is a generated protocol buffer package.

It is generated from these files:
	server-config.proto
	mutation.proto

It has these top-level messages:
	ServerConfig
	AccessPolicy
	Account
	Mutation
	LogTreeHash
	LeafNode
	TreeNode
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

type Permission int32

const (
	Permission_PERM_NONE                    Permission = 0
	Permission_PERM_ALL_PERMISSIONS         Permission = 1
	Permission_PERM_ACCOUNT_LIST_LOGS       Permission = 2
	Permission_PERM_ACCOUNT_LIST_MAPS       Permission = 3
	Permission_PERM_LOG_CREATE              Permission = 4
	Permission_PERM_LOG_DELETE              Permission = 5
	Permission_PERM_MAP_CREATE              Permission = 6
	Permission_PERM_MAP_DELETE              Permission = 7
	Permission_PERM_LOG_RAW_ADD             Permission = 8
	Permission_PERM_LOG_READ_ENTRY          Permission = 9
	Permission_PERM_LOG_READ_HASH           Permission = 10
	Permission_PERM_LOG_PROVE_INCLUSION     Permission = 11
	Permission_PERM_MAP_SET_VALUE           Permission = 12
	Permission_PERM_MAP_GET_VALUE           Permission = 13
	Permission_PERM_MAP_MUTATION_READ_ENTRY Permission = 14
	Permission_PERM_MAP_MUTATION_READ_HASH  Permission = 15
)

var Permission_name = map[int32]string{
	0:  "PERM_NONE",
	1:  "PERM_ALL_PERMISSIONS",
	2:  "PERM_ACCOUNT_LIST_LOGS",
	3:  "PERM_ACCOUNT_LIST_MAPS",
	4:  "PERM_LOG_CREATE",
	5:  "PERM_LOG_DELETE",
	6:  "PERM_MAP_CREATE",
	7:  "PERM_MAP_DELETE",
	8:  "PERM_LOG_RAW_ADD",
	9:  "PERM_LOG_READ_ENTRY",
	10: "PERM_LOG_READ_HASH",
	11: "PERM_LOG_PROVE_INCLUSION",
	12: "PERM_MAP_SET_VALUE",
	13: "PERM_MAP_GET_VALUE",
	14: "PERM_MAP_MUTATION_READ_ENTRY",
	15: "PERM_MAP_MUTATION_READ_HASH",
}
var Permission_value = map[string]int32{
	"PERM_NONE":                    0,
	"PERM_ALL_PERMISSIONS":         1,
	"PERM_ACCOUNT_LIST_LOGS":       2,
	"PERM_ACCOUNT_LIST_MAPS":       3,
	"PERM_LOG_CREATE":              4,
	"PERM_LOG_DELETE":              5,
	"PERM_MAP_CREATE":              6,
	"PERM_MAP_DELETE":              7,
	"PERM_LOG_RAW_ADD":             8,
	"PERM_LOG_READ_ENTRY":          9,
	"PERM_LOG_READ_HASH":           10,
	"PERM_LOG_PROVE_INCLUSION":     11,
	"PERM_MAP_SET_VALUE":           12,
	"PERM_MAP_GET_VALUE":           13,
	"PERM_MAP_MUTATION_READ_ENTRY": 14,
	"PERM_MAP_MUTATION_READ_HASH":  15,
}

func (x Permission) String() string {
	return proto.EnumName(Permission_name, int32(x))
}
func (Permission) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type ServerConfig struct {
	ServerCertPath               string     `protobuf:"bytes,1,opt,name=server_cert_path,json=serverCertPath" json:"server_cert_path,omitempty"`
	ServerKeyPath                string     `protobuf:"bytes,2,opt,name=server_key_path,json=serverKeyPath" json:"server_key_path,omitempty"`
	ListenBind                   string     `protobuf:"bytes,3,opt,name=listen_bind,json=listenBind" json:"listen_bind,omitempty"`
	InsecureHttpServerForTesting bool       `protobuf:"varint,4,opt,name=insecure_http_server_for_testing,json=insecureHttpServerForTesting" json:"insecure_http_server_for_testing,omitempty"`
	Accounts                     []*Account `protobuf:"bytes,5,rep,name=accounts" json:"accounts,omitempty"`
	BoltDbPath                   string     `protobuf:"bytes,6,opt,name=bolt_db_path,json=boltDbPath" json:"bolt_db_path,omitempty"`
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

func (m *ServerConfig) GetAccounts() []*Account {
	if m != nil {
		return m.Accounts
	}
	return nil
}

func (m *ServerConfig) GetBoltDbPath() string {
	if m != nil {
		return m.BoltDbPath
	}
	return ""
}

type AccessPolicy struct {
	ApiKey        string       `protobuf:"bytes,1,opt,name=api_key,json=apiKey" json:"api_key,omitempty"`
	NameMatch     string       `protobuf:"bytes,2,opt,name=name_match,json=nameMatch" json:"name_match,omitempty"`
	AllowedFields []string     `protobuf:"bytes,3,rep,name=allowed_fields,json=allowedFields" json:"allowed_fields,omitempty"`
	Permissions   []Permission `protobuf:"varint,4,rep,packed,name=permissions,enum=continusec.vds.Permission" json:"permissions,omitempty"`
}

func (m *AccessPolicy) Reset()                    { *m = AccessPolicy{} }
func (m *AccessPolicy) String() string            { return proto.CompactTextString(m) }
func (*AccessPolicy) ProtoMessage()               {}
func (*AccessPolicy) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *AccessPolicy) GetApiKey() string {
	if m != nil {
		return m.ApiKey
	}
	return ""
}

func (m *AccessPolicy) GetNameMatch() string {
	if m != nil {
		return m.NameMatch
	}
	return ""
}

func (m *AccessPolicy) GetAllowedFields() []string {
	if m != nil {
		return m.AllowedFields
	}
	return nil
}

func (m *AccessPolicy) GetPermissions() []Permission {
	if m != nil {
		return m.Permissions
	}
	return nil
}

type Account struct {
	Id     string          `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	Policy []*AccessPolicy `protobuf:"bytes,2,rep,name=policy" json:"policy,omitempty"`
}

func (m *Account) Reset()                    { *m = Account{} }
func (m *Account) String() string            { return proto.CompactTextString(m) }
func (*Account) ProtoMessage()               {}
func (*Account) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *Account) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Account) GetPolicy() []*AccessPolicy {
	if m != nil {
		return m.Policy
	}
	return nil
}

func init() {
	proto.RegisterType((*ServerConfig)(nil), "continusec.vds.ServerConfig")
	proto.RegisterType((*AccessPolicy)(nil), "continusec.vds.AccessPolicy")
	proto.RegisterType((*Account)(nil), "continusec.vds.Account")
	proto.RegisterEnum("continusec.vds.Permission", Permission_name, Permission_value)
}

func init() { proto.RegisterFile("server-config.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 586 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x74, 0x93, 0xd1, 0x4f, 0x9b, 0x40,
	0x1c, 0xc7, 0x57, 0xa8, 0xd5, 0xfe, 0x5a, 0xeb, 0xe5, 0x34, 0x4a, 0x5c, 0x17, 0x89, 0xc9, 0x96,
	0x66, 0xc9, 0xfa, 0xa0, 0x7b, 0xdc, 0x0b, 0xb6, 0xa8, 0x8d, 0x14, 0x08, 0x50, 0x97, 0xed, 0xe5,
	0x42, 0xe1, 0xd4, 0xcb, 0x10, 0x08, 0x77, 0xba, 0xf4, 0x4f, 0xd9, 0xdb, 0xde, 0xf7, 0x4f, 0x2e,
	0x1c, 0x88, 0x76, 0x71, 0x6f, 0xf0, 0xf9, 0x7d, 0x8e, 0xfb, 0x7e, 0x7f, 0x09, 0xb0, 0xcb, 0x69,
	0xf1, 0x48, 0x8b, 0x4f, 0x51, 0x96, 0xde, 0xb0, 0xdb, 0x71, 0x5e, 0x64, 0x22, 0xc3, 0x83, 0x28,
	0x4b, 0x05, 0x4b, 0x1f, 0x38, 0x8d, 0xc6, 0x8f, 0x31, 0x3f, 0xfe, 0xad, 0x40, 0xdf, 0x97, 0xde,
	0x44, 0x6a, 0x78, 0x04, 0xa8, 0x3a, 0x47, 0x22, 0x5a, 0x08, 0x92, 0x87, 0xe2, 0x4e, 0x6b, 0xe9,
	0xad, 0x51, 0xd7, 0x1b, 0x54, 0x7c, 0x42, 0x0b, 0xe1, 0x86, 0xe2, 0x0e, 0x7f, 0x80, 0x9d, 0xda,
	0xfc, 0x41, 0x57, 0x95, 0xa8, 0x48, 0x71, 0xbb, 0xc2, 0x57, 0x74, 0x25, 0xbd, 0x23, 0xe8, 0x25,
	0x8c, 0x0b, 0x9a, 0x92, 0x25, 0x4b, 0x63, 0x4d, 0x95, 0x0e, 0x54, 0xe8, 0x8c, 0xa5, 0x31, 0x3e,
	0x07, 0x9d, 0xa5, 0x9c, 0x46, 0x0f, 0x05, 0x25, 0x77, 0x42, 0xe4, 0xa4, 0xfe, 0xec, 0x4d, 0x56,
	0x10, 0x41, 0xb9, 0x60, 0xe9, 0xad, 0xd6, 0xd6, 0x5b, 0xa3, 0x2d, 0x6f, 0xf8, 0xe4, 0x5d, 0x0a,
	0x91, 0x57, 0xb1, 0xcf, 0xb3, 0x22, 0xa8, 0x1c, 0x7c, 0x0a, 0x5b, 0x61, 0x14, 0x65, 0x0f, 0xa9,
	0xe0, 0xda, 0x86, 0xae, 0x8e, 0x7a, 0x27, 0x07, 0xe3, 0xf5, 0xba, 0x63, 0xa3, 0x9a, 0x7b, 0x8d,
	0x88, 0x75, 0xe8, 0x2f, 0xb3, 0x44, 0x90, 0x78, 0x59, 0x55, 0xe8, 0x54, 0xf1, 0x4a, 0x36, 0x5d,
	0x96, 0xf9, 0x8f, 0xff, 0xb4, 0xa0, 0x6f, 0x44, 0x11, 0xe5, 0xdc, 0xcd, 0x12, 0x16, 0xad, 0xf0,
	0x01, 0x6c, 0x86, 0x39, 0x2b, 0x5b, 0xd7, 0x9b, 0xe9, 0x84, 0x39, 0xbb, 0xa2, 0x2b, 0xfc, 0x0e,
	0x20, 0x0d, 0xef, 0x29, 0xb9, 0x0f, 0x45, 0xf4, 0xb4, 0x8c, 0x6e, 0x49, 0xe6, 0x25, 0xc0, 0xef,
	0x61, 0x10, 0x26, 0x49, 0xf6, 0x93, 0xc6, 0xe4, 0x86, 0xd1, 0x24, 0xe6, 0x9a, 0xaa, 0xab, 0xe5,
	0xbe, 0x6a, 0x7a, 0x2e, 0x21, 0xfe, 0x02, 0xbd, 0x9c, 0x16, 0xf7, 0x8c, 0x73, 0x96, 0xa5, 0x5c,
	0x6b, 0xeb, 0xea, 0x68, 0x70, 0x72, 0xf8, 0x6f, 0x13, 0xb7, 0x51, 0xbc, 0x97, 0xfa, 0xb1, 0x03,
	0x9b, 0x75, 0x49, 0x3c, 0x00, 0x85, 0xc5, 0x75, 0x44, 0x85, 0xc5, 0xf8, 0x33, 0x74, 0x72, 0xd9,
	0x40, 0x53, 0xe4, 0x76, 0x86, 0xaf, 0x6c, 0xa7, 0x69, 0xe9, 0xd5, 0xee, 0xc7, 0x5f, 0x2a, 0xc0,
	0xf3, 0x65, 0x78, 0x1b, 0xba, 0xae, 0xe9, 0xcd, 0x89, 0xed, 0xd8, 0x26, 0x7a, 0x83, 0x35, 0xd8,
	0x93, 0xaf, 0x86, 0x65, 0x91, 0xf2, 0x61, 0xe6, 0xfb, 0x33, 0xc7, 0xf6, 0x51, 0x0b, 0x1f, 0xc2,
	0x7e, 0x35, 0x99, 0x4c, 0x9c, 0x85, 0x1d, 0x10, 0x6b, 0xe6, 0x07, 0xc4, 0x72, 0x2e, 0x7c, 0xa4,
	0xbc, 0x3e, 0x9b, 0x1b, 0xae, 0x8f, 0x54, 0xbc, 0x0b, 0x3b, 0x72, 0x66, 0x39, 0x17, 0x64, 0xe2,
	0x99, 0x46, 0x60, 0xa2, 0xf6, 0x1a, 0x9c, 0x9a, 0x96, 0x19, 0x98, 0x68, 0xa3, 0x81, 0x73, 0xc3,
	0x7d, 0x32, 0x3b, 0x6b, 0xb0, 0x36, 0x37, 0xf1, 0x1e, 0xa0, 0xe6, 0xb8, 0x67, 0x7c, 0x25, 0xc6,
	0x74, 0x8a, 0xb6, 0xf0, 0x01, 0xec, 0x3e, 0x53, 0xd3, 0x98, 0x12, 0xd3, 0x0e, 0xbc, 0x6f, 0xa8,
	0x8b, 0xf7, 0x01, 0xaf, 0x0f, 0x2e, 0x0d, 0xff, 0x12, 0x01, 0x1e, 0x82, 0xd6, 0x70, 0xd7, 0x73,
	0xae, 0x4d, 0x32, 0xb3, 0x27, 0xd6, 0xa2, 0x6c, 0x8c, 0x7a, 0xcd, 0xa9, 0xf2, 0x66, 0xdf, 0x0c,
	0xc8, 0xb5, 0x61, 0x2d, 0x4c, 0xd4, 0x5f, 0xe3, 0x17, 0x0d, 0xdf, 0xc6, 0x3a, 0x0c, 0x1b, 0x3e,
	0x5f, 0x04, 0x46, 0x30, 0x73, 0xec, 0x97, 0x39, 0x06, 0xf8, 0x08, 0xde, 0xfe, 0xc7, 0x90, 0x81,
	0x76, 0xce, 0xda, 0xdf, 0x95, 0x7c, 0xb9, 0xec, 0xc8, 0x5f, 0xfb, 0xf4, 0x6f, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xd6, 0xd6, 0x30, 0xd1, 0xf1, 0x03, 0x00, 0x00,
}
