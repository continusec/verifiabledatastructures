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

		root, err := lookupMapHash(kr, treeSize, emptyPath)
		if err != nil {
			return err
		}

		kp := BPathFromKey(req.Key)
		cur, ancestors, err := descendToFork(kr, kp, root)
		if err != nil {
			return err
		}

		proof := make([][]byte, len(ancestors))
		for i := 0; i < len(ancestors); i++ {
			if kp.At(uint(i)) { // right
				proof[i] = ancestors[i].LeftHash
			} else {
				proof[i] = ancestors[i].RightHash
			}
		}

		dataRv, err := lookupDataByLeafHash(kr, pb.LogType_STRUCT_TYPE_MUTATION_LOG, cur.LeafHash)
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
		return nil, err
	}

	return rv, nil
}
