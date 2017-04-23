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
)

// LogTreeHash returns the log tree hash
func (s *localServiceImpl) LogTreeHash(ctx context.Context, req *pb.LogTreeHashRequest) (*pb.LogTreeHashResponse, error) {
	_, err := s.verifyAccessForLogOperation(ctx, req.Log, operationReadHash)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "no access: %s", err)
	}

	if req.TreeSize < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "bad tree size")
	}

	var rv *pb.LogTreeHashResponse
	ns, err := logBucket(req.Log)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unknown err: %s", err)
	}
	err = s.Reader.ExecuteReadOnly(ctx, ns, func(ctx context.Context, kr KeyReader) error {
		head, err := lookupLogTreeHead(ctx, kr, req.Log.LogType)
		if err != nil {
			return err
		}

		// Do we have it already?
		if req.TreeSize == 0 || req.TreeSize == head.TreeSize {
			rv = head
			return nil
		}

		// Are we asking for something silly?
		if req.TreeSize > head.TreeSize {
			return status.Errorf(codes.InvalidArgument, "bad tree size")
		}

		m, err := lookupLogRootHashBySize(ctx, kr, req.Log.LogType, req.TreeSize)
		if err != nil {
			return err
		}

		rv = &pb.LogTreeHashResponse{
			TreeSize: req.TreeSize,
			RootHash: m.Mth,
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
