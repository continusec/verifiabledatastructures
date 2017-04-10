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

// RawDataEntry represents a log/map entry where no special processing is performed, that is,
// the bytes specified are stored as-is, and are used as-is for input to the Merkle Tree leaf function.
type RawDataEntry struct {
	// The data to add
	RawBytes []byte
	leafHash []byte
}

// Data() returns data suitable for downstream processing of this entry by your application.
func (self *RawDataEntry) Data() ([]byte, error) {
	return self.RawBytes, nil
}

// DataForUpload returns the data that should be uploaded
func (self *RawDataEntry) DataForUpload() ([]byte, error) {
	return self.RawBytes, nil
}

func (self *RawDataEntry) DataForStorage() ([]byte, []byte, error) {
	return self.RawBytes, self.RawBytes, nil
}

// Format returns the format suffix should be be appended to the PUT/POST API call
func (self *RawDataEntry) Format() string {
	return ""
}

// LeafHash() returns the leaf hash for this object.
func (self *RawDataEntry) LeafHash() ([]byte, error) {
	if self.leafHash == nil {
		self.leafHash = LeafMerkleTreeHash(self.RawBytes)
	}
	return self.leafHash, nil
}

// RawDataEntryFactoryImpl is a VerifiableEntryFactory that produces JsonEntry instances upon request.
type RawDataEntryFactoryImpl struct{}

// CreateFromBytes creates a new VerifiableEntry given these bytes from the server.
func (self *RawDataEntryFactoryImpl) CreateFromBytes(b []byte) (VerifiableEntry, error) {
	return &RawDataEntry{RawBytes: b}, nil
}

// Format returns the format suffix that should be be appended to the GET call.
func (self *RawDataEntryFactoryImpl) Format() string {
	return ""
}

// RawDataFactory is an instance of RawDataEntryFactoryImpl that is ready for use
var RawDataEntryFactory = &RawDataEntryFactoryImpl{}
