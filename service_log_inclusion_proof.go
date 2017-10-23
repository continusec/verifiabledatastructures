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
	"github.com/continusec/verifiabledatastructures/pb"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"github.com/Guardtime/verifiabledatastructures/vdsoff"
)

func wrapClientError(err error) error {
	switch err {
	case vdsoff.ErrNoSuchKey:
		return vdsoff.ErrNotFound
	default:
		return err
	}
}

// LogInclusionProof returns an inclusion proof
func (s *localServiceImpl) LogInclusionProof(ctx context.Context, req *pb.LogInclusionProofRequest) (*pb.LogInclusionProofResponse, error) {
	_, err := s.verifyAccessForLogOperation(ctx, req.Log, operationProveInclusion)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "no access: %s", err)
	}

	if req.TreeSize < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "extra getting bucket: %s", err)
	}

	var rv *pb.LogInclusionProofResponse
	ns, err := logBucket(req.Log)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "extra getting bucket: %s", err)
	}
	err = s.Reader.ExecuteReadOnly(ctx, ns, func(ctx context.Context, kr KeyReader) error {
		head, err := lookupLogTreeHead(ctx, kr, req.Log.LogType)
		if err != nil {
			return err
		}

		treeSize := req.TreeSize
		if treeSize == 0 {
			treeSize = head.TreeSize
		}

		if treeSize > head.TreeSize {
			return status.Errorf(codes.InvalidArgument, "bad tree size")
		}

		var leafIndex int64
		if len(req.MtlHash) == 0 {
			leafIndex = req.LeafIndex
		} else {
			// Then we must fetch the index
			ei, err := lookupIndexByLeafHash(ctx, kr, req.Log.LogType, req.MtlHash)
			if err != nil {
				return err
			}
			leafIndex = ei.Index
		}

		// We technically shouldn't have found it (it may not be completely written yet)
		if leafIndex < 0 || leafIndex >= head.TreeSize {
			// we use the NotFound error code so that normal usage of GetInclusionProof, that calls this, returns a uniform error.
			return status.Errorf(codes.NotFound, "cannot find it")
		}

		// Client needs a new STH
		if leafIndex >= treeSize {
			return status.Errorf(codes.InvalidArgument, "bad tree size")
		}

		// Ranges are good
		ranges := vdsoff.Path(leafIndex, 0, treeSize)
		path, err := fetchSubTreeHashes(ctx, kr, req.Log.LogType, ranges, false)
		if err != nil {
			return err
		}
		for i, rr := range ranges {
			if len(path[i]) == 0 {
				if vdsoff.IsPow2(rr[1] - rr[0]) {
					// Would have been nice if GetSubTreeHashes could better handle these
					return vdsoff.ErrNotFound
				}
				path[i], err = calcSubTreeHash(ctx, kr, req.Log.LogType, rr[0], rr[1])
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
		_, ok := status.FromError(err)
		if !ok {
			err = status.Errorf(codes.Internal, "unknown err: %s", err)
		}
		return nil, err
	}
	return rv, nil
}


