/*
   Copyright 2017 Continusec Pty Ltd

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package client

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/continusec/objecthash"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/golang/protobuf/proto"
)

func JSONEntryFromProto(m proto.Message) (*pb.LeafData, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return JSONEntry(b)
}

func JSONEntry(data []byte) (*pb.LeafData, error) {
	var o interface{}
	err := json.Unmarshal(data, &o)
	if err != nil {
		return nil, ErrInvalidJSON
	}

	ojb, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}

	bflh, err := objecthash.ObjectHashWithStdRedaction(o)
	if err != nil {
		return nil, err
	}

	return &pb.LeafData{
		LeafInput: bflh,
		ExtraData: ojb,
		Format:    pb.DataFormat_JSON,
	}, nil
}

type LeafDataAuditFunction func(*pb.LeafData) error

// JSONValidateObjectHash verifies that the LeafInput is equal to the objecthash of the ExtraData.
// It ignores the format sent back by the server
func JSONValidateObjectHash(entry *pb.LeafData) error {
	var o interface{}
	err := json.Unmarshal(entry.ExtraData, &o)
	if err != nil {
		return ErrVerificationFailed
	}
	h, err := objecthash.ObjectHashWithStdRedaction(o)
	if err != nil {
		return ErrVerificationFailed
	}
	if !bytes.Equal(entry.LeafInput, h) {
		return ErrVerificationFailed
	}
	return nil
}

// JSONLogAuditFunction verifies that the LeafInput is equal to the objecthash of the ExtraData.
// It ignores the format sent back by the server
func JSONLogAuditFunction(ctx context.Context, idx int64, entry *pb.LeafData) error {
	return JSONValidateObjectHash(entry)
}
