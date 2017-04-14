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
	"log"

	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/golang/protobuf/proto"
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
		log.Println("PROOF KEY", kp.Str())

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
			return ErrNotImplemented
			dataRv = &pb.LeafData{} // empty value suffices
			hmm := BPathCommonPrefixLength(BPath(cur.RemainingPath), kp.Slice(kp.Length()-BPath(cur.RemainingPath).Length(), kp.Length()))
			log.Println("EMPVAL", hmm, ptr)

			if hmm == 0 {
				log.Println("NOMATCHINES", hmm, ptr)

				h, err := calcNodeHash(&pb.MapNode{
					LeafHash:      cur.LeafHash,
					RemainingPath: BPath(cur.RemainingPath).Slice(1, BPath(cur.RemainingPath).Length()),
				}, ptr+1)
				if err != nil {
					return err
				}
				proof[ptr-1] = h
			} else {
				ptr += hmm
				h := cur.LeafHash
				for i, j := BPath(cur.RemainingPath).Length()-1, kp.Length(); j >= uint(ptr+2); i, j = i-1, j-1 {
					if BPath(cur.RemainingPath).At(i) {
						h = client.NodeMerkleTreeHash(defaultLeafValues[j], h)
					} else {
						h = client.NodeMerkleTreeHash(h, defaultLeafValues[j])
					}
				}
				proof[ptr] = h
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
		log.Println("Error getting proof:", err.Error())
		return nil, err
	}

	log.Println(proto.CompactTextString(rv))

	return rv, nil
}
