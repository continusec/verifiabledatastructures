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

package verifiabledatastructures

import (
	"bytes"
	"encoding/json"

	"golang.org/x/net/context"

	"github.com/continusec/objecthash"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/golang/protobuf/proto"
)

// CreateJSONLeafDataFromMutation serializes the map mutation to JSON,
// then deletes the Value.ExtraData before taking the object hash.
// This allows redaction to take place over that value if desired.
func CreateJSONLeafDataFromMutation(mm *pb.MapMutation) (*pb.LeafData, error) {
	data, err := proto.Marshal(mm)
	if err != nil {
		return nil, err
	}
	var m pb.MapMutation
	err = proto.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}

	if m.Value != nil {
		m.Value.ExtraData = nil // we don't need this - TODO, think about some more
		m.Value.Format = 0
	}

	data, err = json.Marshal(m)
	if err != nil {
		return nil, err
	}

	var o interface{}
	err = json.Unmarshal(data, &o)
	if err != nil {
		return nil, ErrInvalidJSON
	}
	bflh, err := objecthash.ObjectHashWithStdRedaction(o)
	if err != nil {
		return nil, err
	}

	bfed, err := json.Marshal(mm)
	if err != nil {
		return nil, err
	}

	return &pb.LeafData{
		LeafInput: bflh,
		ExtraData: bfed,
		Format:    pb.DataFormat_JSON,
	}, nil
}

// CreateJSONLeafData creates a JSON based objecthash for the given JSON bytes.
func CreateJSONLeafData(data []byte) (*pb.LeafData, error) {
	var o interface{}
	err := json.Unmarshal(data, &o)
	if err != nil {
		return nil, ErrInvalidJSON
	}

	bflh, err := objecthash.ObjectHashWithStdRedaction(o)
	if err != nil {
		return nil, err
	}

	return &pb.LeafData{
		LeafInput: bflh,
		ExtraData: data,
		Format:    pb.DataFormat_JSON,
	}, nil
}

// CreateJSONLeafDataFromProto creates a JSON based objecthash for the given proto.
func CreateJSONLeafDataFromProto(m proto.Message) (*pb.LeafData, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return CreateJSONLeafData(b)
}

// CreateJSONLeafDataFromObject creates a JSON based objecthash for the given object.
// The object is first serialized then unmarshalled into a string map.
func CreateJSONLeafDataFromObject(o interface{}) (*pb.LeafData, error) {
	data, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	return CreateJSONLeafData(data)
}

// ValidateJSONLeafData verifies that the LeafInput is equal to the objecthash of the ExtraData.
// It ignores the format field.
func ValidateJSONLeafData(ctx context.Context, entry *pb.LeafData) error {
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

// ShedRedactedJSONFields will parse the JSON, shed any redacted fields,
// and replace othe redactable tuples with the value component only,
// then write back out JSON suitable for parsing into the eventual object
// it should be used in.
func ShedRedactedJSONFields(b []byte) ([]byte, error) {
	var contents interface{}
	err := json.Unmarshal(b, &contents)
	if err != nil {
		return nil, err
	}
	newContents, err := objecthash.UnredactableWithStdPrefix(contents)
	if err != nil {
		return nil, err
	}
	return json.Marshal(newContents)
}

// CreateRedactableJSONLeafData creates a pb.LeafData node with fields suitable
// for redaction, ie it replaces all values with a <nonce, value> tuple.
func CreateRedactableJSONLeafData(data []byte) (*pb.LeafData, error) {
	var o interface{}
	err := json.Unmarshal(data, &o)
	if err != nil {
		return nil, ErrInvalidJSON
	}

	o, err = objecthash.Redactable(o)
	if err != nil {
		return nil, err
	}

	ojb, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}

	bflh, err := objecthash.ObjectHash(o)
	if err != nil {
		return nil, err
	}

	return &pb.LeafData{
		LeafInput: bflh,
		ExtraData: ojb,
		Format:    pb.DataFormat_JSON,
	}, nil
}

// ValidateJSONLeafDataFromMutation verifies that the LeafInput is equal to the objecthash of the ExtraData.
// It does not valid the underlying leaf node extra data derives the leaf input.
// It ignores the format field.
func ValidateJSONLeafDataFromMutation(entry *pb.LeafData) error {
	var o *pb.MapMutation
	err := json.Unmarshal(entry.ExtraData, &o)
	if err != nil {
		return ErrVerificationFailed
	}
	if o.Value != nil {
		o.Value.ExtraData = nil
		o.Value.Format = 0
	}

	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	var o2 interface{}
	err = json.Unmarshal(data, &o2)
	if err != nil {
		return err
	}

	h, err := objecthash.ObjectHashWithStdRedaction(o2)
	if err != nil {
		return ErrVerificationFailed
	}
	if !bytes.Equal(entry.LeafInput, h) {
		return ErrVerificationFailed
	}

	return nil
}
