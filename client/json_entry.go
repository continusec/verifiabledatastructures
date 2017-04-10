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
	"encoding/json"

	"github.com/continusec/objecthash"
)

// JsonEntry should used when entry MerkleTreeLeafs should be based on ObjectHash rather than the JSON bytes directly.
// Since there is no canonical encoding for JSON, it is useful to hash these objects in a more defined manner.
type JsonEntry struct {
	// The data to add
	JsonBytes []byte
	leafHash  []byte
}

// Data() returns data suitable for downstream processing of this entry by your application.
func (self *JsonEntry) Data() ([]byte, error) {
	return self.JsonBytes, nil
}

// DataForUpload returns the data that should be uploaded
func (self *JsonEntry) DataForUpload() ([]byte, error) {
	return self.JsonBytes, nil
}

func (self *JsonEntry) DataForStorage() ([]byte, []byte, error) {
	var o interface{}
	err := json.Unmarshal(self.JsonBytes, &o)
	if err != nil {
		return nil, nil, ErrInvalidJSON
	}

	bflh, err := objecthash.ObjectHash(o)
	if err != nil {
		return nil, nil, err
	}

	return bflh, self.JsonBytes, nil
}

// Format returns the format suffix should be be appended to the PUT/POST API call
func (self *JsonEntry) Format() string {
	return "/xjson"
}

// LeafHash() returns the leaf hash for this object.
func (self *JsonEntry) LeafHash() ([]byte, error) {
	if self.leafHash == nil {
		if len(self.JsonBytes) == 0 {
			self.leafHash = LeafMerkleTreeHash(nil)
		} else {
			var contents interface{}
			err := json.Unmarshal(self.JsonBytes, &contents)
			if err != nil {
				return nil, err
			}
			oh, err := objecthash.ObjectHashWithStdRedaction(contents)
			if err != nil {
				return nil, err
			}
			self.leafHash = LeafMerkleTreeHash(oh)
		}
	}
	return self.leafHash, nil
}

// JsonEntryFactoryImpl is a VerifiableEntryFactory that produces JsonEntry instances upon request.
type JsonEntryFactoryImpl struct{}

// CreateFromBytes creates a new VerifiableEntry given these bytes from the server.
func (self *JsonEntryFactoryImpl) CreateFromBytes(b []byte) (VerifiableEntry, error) {
	return &JsonEntry{JsonBytes: b}, nil
}

// Format returns the format suffix that should be be appended to the GET call.
func (self *JsonEntryFactoryImpl) Format() string {
	return "/xjson"
}

// JsonEntryFactory is an instance of JsonEntryFactoryImpl that is ready for use
var JsonEntryFactory = &JsonEntryFactoryImpl{}
