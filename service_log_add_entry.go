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
	"github.com/continusec/verifiabledatastructures/util"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LogAddEntry adds an entry to a log
func (s *localServiceImpl) LogAddEntry(ctx context.Context, req *pb.LogAddEntryRequest) (*pb.LogAddEntryResponse, error) {
	_, err := s.verifyAccessForLogOperation(ctx, req.Log, operationRawAdd)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "no access: %s", err)
	}

	if req.Log.LogType != pb.LogType_STRUCT_TYPE_LOG {
		return nil, status.Errorf(codes.InvalidArgument, "wrong log type")
	}

	ns, err := logBucket(req.Log)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "extra getting bucket: %s", err)
	}

	err = s.Mutator.QueueMutation(ctx, ns, &pb.Mutation{
		LogAddEntry: req,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error queuing mutation: %s", err)
	}

	return &pb.LogAddEntryResponse{
		LeafHash: util.LeafMerkleTreeHash(req.Value.LeafInput),
	}, nil
}
