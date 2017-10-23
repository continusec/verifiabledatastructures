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

// MapTreeHash returns the tree hash for a map
func (s *localServiceImpl) MapTreeHash(ctx context.Context, req *pb.MapTreeHashRequest) (*pb.MapTreeHashResponse, error) {
	_, err := s.verifyAccessForMap(ctx, req.Map, pb.Permission_PERM_MAP_GET_VALUE)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "no access: %s", err)
	}

	if req.TreeSize < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "bad tree size")
	}

	var rv *pb.MapTreeHashResponse
	ns, err := mapBucket(req.Map)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unknown err: %s", err)
	}
	err = s.Reader.ExecuteReadOnly(ctx, ns, func(ctx context.Context, kr KeyReader) error {
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

		// Need this for response
		mutHead, err := lookupLogRootHashBySize(ctx, kr, pb.LogType_STRUCT_TYPE_MUTATION_LOG, treeSize)
		if err != nil {
			return err
		}

		// Get the root node for tree size
		mapNode, err := lookupMapHash(ctx, kr, treeSize, vdsoff.BPathEmpty)
		if err != nil {
			return err
		}

		rh, err := vdsoff.CalcNodeHash(mapNode, 0)
		if err != nil {
			return err
		}

		rv = &pb.MapTreeHashResponse{
			RootHash: rh,
			MutationLog: &pb.LogTreeHashResponse{
				RootHash: mutHead.Mth,
				TreeSize: treeSize,
			},
		}
		return nil
	})
	if err != nil {
		_, ok := status.FromError(err)
		if !ok {
			err = status.Errorf(codes.Internal, "unknown err: %s", err)
		}
	}

	return rv, nil
}
