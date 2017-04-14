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

// RedactableJsonEntry  represents JSON data should be made Redactable by the server upon upload.
// ie change all dictionary values to be nonce-value tuples and control access to fields based on the API key used to make the request.
// This class is for entries that should be uploaded. Entries that are returned are of type RedactedJsonEntry.
type RedactableJsonEntry struct {
	// The data to add
	JsonBytes []byte
	leafHash  []byte
}

func (self *RedactableJsonEntry) GetLeafInput() []byte {
	return self.JsonBytes // TODO - wrong here to compile
}
func (self *RedactableJsonEntry) GetExtraData() []byte {
	return nil // TODO - wrong here to compile
}

// DataForUpload returns the data that should be uploaded
func (self *RedactableJsonEntry) DataForUpload() ([]byte, error) {
	return self.JsonBytes, nil
}

func (self *RedactableJsonEntry) DataForStorage() ([]byte, []byte, error) {
	var o interface{}
	err := json.Unmarshal(self.JsonBytes, &o)
	if err != nil {
		return nil, nil, ErrInvalidJSON
	}

	o, err = objecthash.Redactable(o)
	if err != nil {
		return nil, nil, err
	}

	ojb, err := json.Marshal(o)
	if err != nil {
		return nil, nil, err
	}

	bflh, err := objecthash.ObjectHash(o)
	if err != nil {
		return nil, nil, err
	}

	return bflh, ojb, nil
}

// Format returns the format suffix should be be appended to the PUT/POST API call
func (self *RedactableJsonEntry) Format() string {
	return "/xjson/redactable"
}

// RedactedJsonEntry represents redacted entries as returned by the server.
// Not to be confused with RedactableJsonEntry that should be used to represent objects that
// should be made redactable by the server when uploaded.
type RedactedJsonEntry struct {
	// The data returned
	RedactedJsonBytes []byte
	shedBytes         []byte
	leafHash          []byte
}

// Data() returns data suitable for downstream processing of this entry by your application.
func (self *RedactedJsonEntry) Data() ([]byte, error) {
	if self.shedBytes == nil {
		var contents interface{}
		err := json.Unmarshal(self.RedactedJsonBytes, &contents)
		if err != nil {
			return nil, err
		}
		newContents, err := objecthash.UnredactableWithStdPrefix(contents)
		if err != nil {
			return nil, err
		}
		self.shedBytes, err = json.Marshal(newContents)
		if err != nil {
			return nil, err
		}
	}
	return self.shedBytes, nil
}

// LeafHash() returns the leaf hash for this object.
func (self *RedactedJsonEntry) LeafHash() ([]byte, error) {
	if self.leafHash == nil {
		if len(self.RedactedJsonBytes) == 0 {
			self.leafHash = LeafMerkleTreeHash(nil)
		} else {
			var contents interface{}
			err := json.Unmarshal(self.RedactedJsonBytes, &contents)
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

// RedactedJsonEntryFactoryImpl is a VerifiableEntryFactory that produces RedactedJsonEntry instances upon request.
type RedactedJsonEntryFactoryImpl struct{}

// CreateFromBytes creates a new VerifiableEntry given these bytes from the server.
func (self *RedactedJsonEntryFactoryImpl) CreateFromBytes(b []byte) (VerifiableEntry, error) {
	return &RedactedJsonEntry{RedactedJsonBytes: b}, nil
}

// Format returns the format suffix that should be be appended to the GET call.
func (self *RedactedJsonEntryFactoryImpl) Format() string {
	return "/xjson"
}

// RedactedJsonEntryFactory is an instance of RedactedJsonEntryFactoryImpl that is ready for use
var RedactedJsonEntryFactory = &RedactedJsonEntryFactoryImpl{}
