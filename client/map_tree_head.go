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
	"encoding/base64"

	"github.com/continusec/objecthash"
)

// MapTreeHead is a class for Tree Head as returned for a Map with a given size.
type MapTreeHead struct {
	// RootHash is the root hash for map of size MutationLogTreeHead.TreeSize
	RootHash []byte

	// MutationLogTreeHead is the mutation log tree head for which this RootHash is valid
	MutationLogTreeHead LogTreeHead

	leafHash []byte
}

// TreeSize is a utility method to return the tree size of the underlying mutation log.
func (self *MapTreeHead) TreeSize() int64 {
	return self.MutationLogTreeHead.TreeSize
}

// LeafHash allows for this MapTreeHead to implement MerkleTreeLeaf which makes it
// convenient for use with inclusion proof checks against the TreeHead log.
func (self *MapTreeHead) LeafHash() ([]byte, error) {
	if self.leafHash == nil {
		oh, err := objecthash.ObjectHash(map[string]interface{}{
			"map_hash": base64.StdEncoding.EncodeToString(self.RootHash), // Our hashes are encoded as base64 in JSON, so use this as input to objecthash
			"mutation_log": map[string]interface{}{
				"tree_size": float64(self.TreeSize()),                                             // JSON knows only numbers, so sadly we pretend to be a float
				"tree_hash": base64.StdEncoding.EncodeToString(self.MutationLogTreeHead.RootHash), // Our hashes are encoded as base64 in JSON, so use this as input to objecthash
			},
		})
		if err != nil {
			return nil, err
		}
		self.leafHash = LeafMerkleTreeHash(oh)
	}
	return self.leafHash, nil
}
