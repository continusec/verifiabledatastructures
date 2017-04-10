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

// AddEntryResponse represents a response from a call to add an entry to a log or map
type AddEntryResponse struct {
	// EntryLeafHash is the Merkle Tree Leaf hash of the item as added
	EntryLeafHash []byte
}

// LeafHash() returns the leaf hash for this object.
func (self *AddEntryResponse) LeafHash() ([]byte, error) {
	return self.EntryLeafHash, nil
}
