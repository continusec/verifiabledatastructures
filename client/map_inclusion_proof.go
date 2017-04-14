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
	"log"
)

// MapInclusionProof represents the response for getting an entry from a map. It contains both the value itself,
// as well as an inclusion proof for how that value fits into the map root hash.
type MapInclusionProof struct {
	// Key is the key for which this inclusion proof is valid
	Key []byte

	// Value represents the entry for which this proof is valid
	Value VerifiableEntry

	// AuditPath is the set of Merkle Tree Hashes needed to prove consistency
	AuditPath [][]byte

	// TreeSize is the size of the tree for which this proof is valid
	TreeSize int64
}

// Verify verifies an inclusion proof against a MapTreeHead
func (self *MapInclusionProof) Verify(head *MapTreeHead) error {
	if self.TreeSize != head.MutationLogTreeHead.TreeSize {
		log.Println("reason1")
		return ErrVerificationFailed
	}

	log.Printf("%+#v\n", self)
	log.Printf("%+#v\n", self.Value)

	kp := ConstructMapKeyPath(self.Key)
	t, err := self.Value.LeafHash()
	if err != nil {
		return err
	}
	for i := len(kp) - 1; i >= 0; i-- {
		p := self.AuditPath[i]
		if p == nil {
			p = defaultLeafValues[i+1]
		}

		if kp[i] {
			t = NodeMerkleTreeHash(p, t)
		} else {
			t = NodeMerkleTreeHash(t, p)
		}
	}

	if !bytes.Equal(t, head.RootHash) {
		log.Println("reason2", self.AuditPath)
		return ErrVerificationFailed
	}

	// should not happen, but guarding anyway
	if len(t) != 32 {
		log.Println("reason3")
		return ErrVerificationFailed
	}

	// all clear
	return nil
}
