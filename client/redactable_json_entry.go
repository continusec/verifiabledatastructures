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
	"encoding/json"

	"github.com/continusec/objecthash"
	"github.com/continusec/verifiabledatastructures/pb"
)

func ShedRedacted(b []byte) ([]byte, error) {
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

// VerifyAndShedRedacted verifies that the LeafInput in data is the
// objecthash of the ExtraData, it then sheds redacted fields, and converts
// redactible tuples to values, finally re-serializing JSON and returning.
func VerifyAndShedRedacted(data *pb.LeafData) ([]byte, error) {
	var contents interface{}
	err := json.Unmarshal(data.ExtraData, &contents)
	if err != nil {
		return nil, err
	}
	oh, err := objecthash.ObjectHashWithStdRedaction(contents)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(oh, data.LeafInput) {
		return nil, ErrVerificationFailed
	}
	newContents, err := objecthash.UnredactableWithStdPrefix(contents)
	if err != nil {
		return nil, err
	}
	return json.Marshal(newContents)
}

func RedactableJsonEntry(data []byte) (*pb.LeafData, error) {
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
