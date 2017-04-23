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
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func wrapClientError(err error) error {
	switch err {
	case ErrNoSuchKey:
		return ErrNotFound
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
		ranges := Path(leafIndex, 0, treeSize)
		path, err := fetchSubTreeHashes(ctx, kr, req.Log.LogType, ranges, false)
		if err != nil {
			return err
		}
		for i, rr := range ranges {
			if len(path[i]) == 0 {
				if IsPow2(rr[1] - rr[0]) {
					// Would have been nice if GetSubTreeHashes could better handle these
					return ErrNotFound
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

// VerifyLogInclusionProof verifies an inclusion proof against a LogTreeHead
func VerifyLogInclusionProof(self *pb.LogInclusionProofResponse, leafHash []byte, head *pb.LogTreeHashResponse) error {
	if self.TreeSize != head.TreeSize {
		return ErrVerificationFailed
	}
	if self.LeafIndex >= self.TreeSize {
		return ErrVerificationFailed
	}
	if self.LeafIndex < 0 {
		return ErrVerificationFailed
	}

	fn, sn := self.LeafIndex, self.TreeSize-1
	r := leafHash
	for _, p := range self.AuditPath {
		if (fn == sn) || ((fn & 1) == 1) {
			r = NodeMerkleTreeHash(p, r)
			for !((fn == 0) || ((fn & 1) == 1)) {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeMerkleTreeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return ErrVerificationFailed
	}
	if !bytes.Equal(r, head.RootHash) {
		return ErrVerificationFailed
	}

	// should not happen, but guarding anyway
	if len(r) != 32 {
		return ErrVerificationFailed
	}

	// all clear
	return nil
}
