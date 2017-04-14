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
	"bytes"

	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/pb"
)

func (s *LocalService) MapGetValue(ctx context.Context, req *pb.MapGetValueRequest) (*pb.MapGetValueResponse, error) {
	err := s.verifyAccessForMap(req.Map, pb.Permission_PERM_MAP_GET_VALUE)
	if err != nil {
		return nil, err
	}

	return nil, ErrNotImplemented

	if req.TreeSize < 0 {
		return nil, ErrInvalidTreeRange
	}

	var rv *pb.MapGetValueResponse
	ns, err := mapBucket(req.Map)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	err = s.Reader.ExecuteReadOnly(ns, func(kr KeyReader) error {
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

		prv := [256][]byte{}
		var dataRv *pb.LeafData
		cur, err := lookupMapHash(kr, treeSize, nil)
		if err != nil {
			return err
		}

		kp := BPathFromKey(req.Key)
		ptr := uint(0)
		for i := uint(0); i < kp.Length(); i++ {
			var nnum int64
			if kp.At(i) { // right
				prv[i] = cur.LeftHash
				nnum = cur.RightNumber
			} else {
				prv[i] = cur.RightHash
				nnum = cur.LeftNumber
			}
			if nnum == 0 {
				break
			} else {
				cur, err = lookupMapHash(kr, nnum, kp.Slice(0, i+1))
				if err != nil {
					return err
				}
				ptr++
			}
		}

		hmm := BPathCommonPrefixLength(cur.RemainingPath, kp.Slice(ptr, kp.Length()))
		if len(cur.LeafHash) != 0 && hmm == BPath(cur.RemainingPath).Length() {
			// winner winner chicken dinner, no more work needed.
			if bytes.Equal(cur.LeafHash, nullLeafHash) {
				rv = nil
			} else {
				dataRv, err = lookupDataByLeafHash(kr, pb.LogType_STRUCT_TYPE_MUTATION_LOG, cur.LeafHash)
				if err != nil {
					return err
				}
			}
		} else {
			if hmm > 0 {
				ptr += hmm
				h := cur.LeafHash
				if len(h) != 0 { // special case, root is empty node
					for i, j := int(BPath(cur.RemainingPath).Length()-1), int(kp.Length()); j >= int(ptr+2); i, j = i-1, j-1 {
						if BPath(cur.RemainingPath).At(uint(i)) {
							h = client.NodeMerkleTreeHash(defaultLeafValues[j], h)
						} else {
							h = client.NodeMerkleTreeHash(h, defaultLeafValues[j])
						}
					}
					prv[ptr] = h
				}
			}
		}

		rv = &pb.MapGetValueResponse{
			AuditPath: prv[:],
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
