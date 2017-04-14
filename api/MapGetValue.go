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

package api

import (
	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/pb"
)

func (s *LocalService) MapGetValue(ctx context.Context, req *pb.MapGetValueRequest) (*pb.MapGetValueResponse, error) {
	err := s.verifyAccessForMap(req.Map, pb.Permission_PERM_MAP_GET_VALUE)
	if err != nil {
		return nil, err
	}

	if req.TreeSize < 0 {
		return nil, ErrInvalidTreeRange
	}

	var rv *pb.MapGetValueResponse
	ns, err := mapBucket(req.Map)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	err = s.Reader.ExecuteReadOnly(ns, func(kr KeyReader) error {
		kp := BPathFromKey(req.Key)

		th, err := lookupLogTreeHead(kr, pb.LogType_STRUCT_TYPE_TREEHEAD_LOG)
		if err != nil {
			return err
		}
		treeSize := req.TreeSize
		if treeSize == 0 {
			treeSize = th.TreeSize
		}

		// Are we asking for something silly?
		if treeSize > th.TreeSize {
			return ErrInvalidTreeRange
		}

		root, err := lookupMapHash(kr, treeSize, BPathEmpty)

		if err != nil {
			return err
		}

		cur, ancestors, err := descendToFork(kr, kp, root)
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
		// Check value is actually us, else we need to manufacture a proof
		if mapNodeRemainingMatches(cur, kp) {
			dataRv, err = lookupDataByLeafHash(kr, pb.LogType_STRUCT_TYPE_MUTATION_LOG, cur.LeafHash)
			if err != nil {
				return err
			}
		} else {
			//return ErrNotImplemented
			dataRv = &pb.LeafData{} // empty value suffices

			// Add empty proof paths for common ancestors
			for BPath(cur.RemainingPath).Length() != 0 && kp.At(ptr) == BPath(cur.RemainingPath).At(0) {
				cur = &pb.MapNode{
					LeafHash:      cur.LeafHash,
					RemainingPath: BPath(cur.RemainingPath).Slice(1, BPath(cur.RemainingPath).Length()), // not efficient - let's get it correct first and tidy up ldate
				}
				ptr++
			}

			// Now we create a new parent with two children, us and the previous node.
			// Was the previous node a leaf? (if not, we can skip the sibling bit)
			if isLeaf(cur) {
				// Start with writing the sibling
				them := &pb.MapNode{
					LeafHash:      cur.LeafHash,
					RemainingPath: BPath(cur.RemainingPath).Slice(1, BPath(cur.RemainingPath).Length()),
				}

				theirHash, err := calcNodeHash(them, uint(ptr+1))
				if err != nil {
					return err
				}
				proof[ptr] = theirHash
				ptr++
			} else {
				if kp.At(ptr) { // right
					proof[ptr] = cur.LeftHash
				} else {
					proof[ptr] = cur.RightHash
				}
				ptr++ // slap another shrimp on the barbie, one of the above sides will get overwitten when we write out ancestors
			}

		}

		rv = &pb.MapGetValueResponse{
			AuditPath: proof,
			TreeSize:  treeSize,
			Value:     dataRv,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return rv, nil
}
