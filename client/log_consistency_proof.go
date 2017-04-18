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

	"github.com/continusec/verifiabledatastructures/pb"
)

// VerifyLogConsistencyProof will verify that the consistency proof stored in this object can produce both the LogTreeHeads passed to this method.
func VerifyLogConsistencyProof(self *pb.LogConsistencyProofResponse, first, second *pb.LogTreeHashResponse) error {
	if first.TreeSize != self.FromSize {
		return ErrVerificationFailed
	}

	if second.TreeSize != self.TreeSize {
		return ErrVerificationFailed
	}

	if self.FromSize < 1 {
		return ErrVerificationFailed
	}

	if self.FromSize >= second.TreeSize {
		return ErrVerificationFailed
	}

	var proof [][]byte
	if IsPow2(self.FromSize) {
		proof = make([][]byte, 1+len(self.AuditPath))
		proof[0] = first.RootHash
		copy(proof[1:], self.AuditPath)
	} else {
		proof = self.AuditPath
	}

	fn, sn := self.FromSize-1, second.TreeSize-1
	for 1 == (fn & 1) {
		fn >>= 1
		sn >>= 1
	}
	if len(proof) == 0 {
		return ErrVerificationFailed
	}
	fr := proof[0]
	sr := proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return ErrVerificationFailed
		}
		if (1 == (fn & 1)) || (fn == sn) {
			fr = NodeMerkleTreeHash(c, fr)
			sr = NodeMerkleTreeHash(c, sr)
			for !((fn == 0) || (1 == (fn & 1))) {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeMerkleTreeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return ErrVerificationFailed
	}

	if !bytes.Equal(first.RootHash, fr) {
		return ErrVerificationFailed
	}

	if !bytes.Equal(second.RootHash, sr) {
		return ErrVerificationFailed
	}

	// should not happen, but guarding anyway
	if len(fr) != 32 {
		return ErrVerificationFailed
	}
	if len(sr) != 32 {
		return ErrVerificationFailed
	}

	// all clear
	return nil
}
