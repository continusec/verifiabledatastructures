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

import "bytes"

// LogInclusionProof is a class to represent a consistency proof for a given log.
type LogInclusionProof struct {
	// AuditPath is the set of Merkle Tree Hashes needed to prove inclusion
	AuditPath [][]byte

	// TreeSize is the size of the tree for which this proof is valid
	TreeSize int64

	// LeafIndex is the index of this leaf within the tree
	LeafIndex int64

	// LeafHash is the Merkle Tree Leaf hash for which this proof is based
	LeafHash []byte
}

// Verify verifies an inclusion proof against a LogTreeHead
func (self *LogInclusionProof) Verify(head *LogTreeHead) error {
	if self.TreeSize != head.TreeSize {
		return ErrVerificationFailed
	}
	if self.LeafIndex >= self.TreeSize {
		return ErrVerificationFailed
	}
	if self.LeafIndex < 0 {
		return ErrVerificationFailed
	}

	fn, sn := self.LeafIndex, self.TreeSize-1
	r := self.LeafHash
	for _, p := range self.AuditPath {
		if (fn == sn) || ((fn & 1) == 1) {
			r = NodeMerkleTreeHash(p, r)
			for !((fn == 0) || ((fn & 1) == 1)) {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeMerkleTreeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return ErrVerificationFailed
	}
	if !bytes.Equal(r, head.RootHash) {
		return ErrVerificationFailed
	}

	// should not happen, but guarding anyway
	if len(r) != 32 {
		return ErrVerificationFailed
	}

	// all clear
	return nil
}
