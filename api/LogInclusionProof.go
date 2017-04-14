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

	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/pb"
)

func (s *LocalService) LogInclusionProof(ctx context.Context, req *pb.LogInclusionProofRequest) (*pb.LogInclusionProofResponse, error) {
	err := s.verifyAccessForLogOperation(req.Log, operationProveInclusion)
	if err != nil {
		return nil, err
	}

	if req.TreeSize < 0 {
		return nil, ErrInvalidTreeRange
	}

	var rv *pb.LogInclusionProofResponse
	ns, err := logBucket(req.Log)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	err = s.Reader.ExecuteReadOnly(ns, func(kr KeyReader) error {
		head, err := lookupLogTreeHead(kr, req.Log.LogType)
		if err != nil {
			return err
		}

		treeSize := req.TreeSize
		if treeSize == 0 {
			treeSize = head.TreeSize
		}

		if treeSize > head.TreeSize {
			return ErrInvalidTreeRange
		}

		var leafIndex int64
		if len(req.MtlHash) == 0 {
			leafIndex = req.LeafIndex
		} else {
			// Then we must fetch the index
			ei, err := lookupIndexByLeafHash(kr, req.Log.LogType, req.MtlHash)
			if err != nil {
				return err
			}
			leafIndex = ei.Index
		}

		// We technically shouldn't have found it (it may not be completely written yet)
		if leafIndex < 0 || leafIndex >= head.TreeSize {
			// we use the NotFound error code so that normal usage of GetInclusionProof, that calls this, returns a uniform error.
			return ErrNoSuchKey
		}

		// Client needs a new STH
		if leafIndex >= treeSize {
			return ErrInvalidTreeRange
		}

		// Ranges are good
		ranges := client.Path(leafIndex, 0, treeSize)
		path, err := fetchSubTreeHashes(kr, req.Log.LogType, ranges, false)
		if err != nil {
			return err
		}
		for i, rr := range ranges {
			if len(path[i]) == 0 {
				if client.IsPow2(rr[1] - rr[0]) {
					// Would have been nice if GetSubTreeHashes could better handle these
					return ErrNoSuchKey
				}
				path[i], err = calcSubTreeHash(kr, req.Log.LogType, rr[0], rr[1])
				if err != nil {
					return err
				}
			}
		}

		rv = &pb.LogInclusionProofResponse{
			LeafIndex: leafIndex,
			TreeSize:  treeSize,
			AuditPath: path,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rv, nil
}
