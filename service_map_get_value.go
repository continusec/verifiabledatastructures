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

package verifiabledatastructures

import (
	"bytes"

	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/util"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MapGetValue returns a value from a map
func (s *localServiceImpl) MapGetValue(ctx context.Context, req *pb.MapGetValueRequest) (*pb.MapGetValueResponse, error) {
	am, err := s.verifyAccessForMap(ctx, req.Map, pb.Permission_PERM_MAP_GET_VALUE)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "no access: %s", err)
	}

	if req.TreeSize < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "bad tree size")
	}

	var rv *pb.MapGetValueResponse
	ns, err := mapBucket(req.Map)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unknown err: %s", err)
	}
	err = s.Reader.ExecuteReadOnly(ctx, ns, func(ctx context.Context, kr KeyReader) error {
		kp := util.BPathFromKey(req.Key)

		th, err := lookupLogTreeHead(ctx, kr, pb.LogType_STRUCT_TYPE_TREEHEAD_LOG)
		if err != nil {
			return err
		}
		treeSize := req.TreeSize
		if treeSize == 0 {
			treeSize = th.TreeSize
		}

		// Are we asking for something silly?
		if treeSize > th.TreeSize {
			return status.Errorf(codes.InvalidArgument, "bad tree size")
		}

		root, err := lookupMapHash(ctx, kr, treeSize, util.BPathEmpty)

		if err != nil {
			return err
		}

		cur, ancestors, err := descendToFork(ctx, kr, kp, root)
		if err != nil {
			return err
		}

		proof := make([][]byte, kp.Length())
		ptr := uint(0)
		for i := 0; i < len(ancestors); i++ {
			if kp.At(uint(i)) { // right
				proof[i] = ancestors[i].LeftHash
			} else {
				proof[i] = ancestors[i].RightHash
			}
			ptr++
		}

		var dataRv *pb.LeafData
		if len(cur.LeafHash) == 0 { // we're a node
			dataRv = &pb.LeafData{} // empty value
			if kp.At(ptr) {         // right
				proof[ptr] = cur.LeftHash
			} else {
				proof[ptr] = cur.RightHash
			}
		} else { // we're a leaf
			// Check value is actually us, else we need to manufacture a proof
			if bytes.Equal(kp, cur.Path) {
				if bytes.Equal(cur.LeafHash, nullLeafHash) {
					dataRv = &pb.LeafData{} // empty value
				} else {
					dataRv, err = lookupDataByLeafHash(ctx, kr, pb.LogType_STRUCT_TYPE_MUTATION_LOG, cur.LeafHash)
					if err != nil {
						return err
					}
				}
			} else {
				dataRv = &pb.LeafData{} // empty value

				// Add empty proof paths for common ancestors
				for kp.At(ptr) == util.BPath(cur.Path).At(ptr) {
					ptr++
				}

				// Add sibling hash
				theirHash, err := util.CalcNodeHash(cur, uint(ptr+1))
				if err != nil {
					return err
				}
				proof[ptr] = theirHash
			}
		}

		// Check for fields that need redacting
		dataRv, err = filterLeafData(dataRv, am)
		if err != nil {
			return err
		}

		rv = &pb.MapGetValueResponse{
			AuditPath: proof,
			TreeSize:  treeSize,
			Value:     dataRv,
		}
		return nil
	})

	if err != nil {
		_, ok := status.FromError(err)
		if !ok {
			err = status.Errorf(codes.Internal, "unknown err: %s", err)
		}
		return nil, err
	}

	return rv, nil
}

// VerifyMapInclusionProof verifies an inclusion proof against a MapTreeHead
func VerifyMapInclusionProof(self *pb.MapGetValueResponse, key []byte, head *pb.MapTreeHashResponse) error {
	if self.TreeSize != head.MutationLog.TreeSize {
		return util.ErrVerificationFailed
	}

	kp := util.ConstructMapKeyPath(key)
	t := util.LeafMerkleTreeHash(self.Value.GetLeafInput())
	for i := len(kp) - 1; i >= 0; i-- {
		p := self.AuditPath[i]
		if len(p) == 0 { // some transport layers change nil to zero length, so we handle either in the same way
			p = util.DefaultLeafValues[i+1]
		}

		if kp[i] {
			t = util.NodeMerkleTreeHash(p, t)
		} else {
			t = util.NodeMerkleTreeHash(t, p)
		}
	}

	if !bytes.Equal(t, head.RootHash) {
		return util.ErrVerificationFailed
	}

	// should not happen, but guarding anyway
	if len(t) != 32 {
		return util.ErrVerificationFailed
	}

	// all clear
	return nil
}
