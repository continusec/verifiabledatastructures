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
	"golang.org/x/net/context"
)

// MapTreeHash returns the tree hash for a map
func (s *LocalService) MapTreeHash(ctx context.Context, req *MapTreeHashRequest) (*MapTreeHashResponse, error) {
	_, err := s.verifyAccessForMap(req.Map, Permission_PERM_MAP_GET_VALUE)
	if err != nil {
		return nil, err
	}

	if req.TreeSize < 0 {
		return nil, ErrInvalidTreeRange
	}

	var rv *MapTreeHashResponse
	ns, err := mapBucket(req.Map)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	err = s.Reader.ExecuteReadOnly(ns, func(kr KeyReader) error {
		th, err := lookupLogTreeHead(kr, LogType_STRUCT_TYPE_TREEHEAD_LOG)
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

		// Need this for response
		mutHead, err := lookupLogRootHashBySize(kr, LogType_STRUCT_TYPE_MUTATION_LOG, treeSize)
		if err != nil {
			return err
		}

		// Get the root node for tree size
		mapNode, err := lookupMapHash(kr, treeSize, BPathEmpty)
		if err != nil {
			return err
		}

		rh, err := calcNodeHash(mapNode, 0)
		if err != nil {
			return err
		}

		rv = &MapTreeHashResponse{
			RootHash: rh,
			MutationLog: &LogTreeHashResponse{
				RootHash: mutHead.Mth,
				TreeSize: treeSize,
			},
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return rv, nil
}
