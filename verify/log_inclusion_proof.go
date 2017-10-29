package verify

import (
	"bytes"

	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/util"
)

// VerifyLogInclusionProof verifies an inclusion proof against a LogTreeHead
func VerifyLogInclusionProof(self *pb.LogInclusionProofResponse, leafHash []byte, head *pb.LogTreeHashResponse) error {
	if self.TreeSize != head.TreeSize {
		return util.ErrVerificationFailed
	}
	if self.LeafIndex >= self.TreeSize {
		return util.ErrVerificationFailed
	}
	if self.LeafIndex < 0 {
		return util.ErrVerificationFailed
	}

	fn, sn := self.LeafIndex, self.TreeSize-1
	r := leafHash
	for _, p := range self.AuditPath {
		if (fn == sn) || ((fn & 1) == 1) {
			r = util.NodeMerkleTreeHash(p, r)
			for !((fn == 0) || ((fn & 1) == 1)) {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = util.NodeMerkleTreeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return util.ErrVerificationFailed
	}
	if !bytes.Equal(r, head.RootHash) {
		return util.ErrVerificationFailed
	}

	// should not happen, but guarding anyway
	if len(r) != 32 {
		return util.ErrVerificationFailed
	}

	// all clear
	return nil
}
