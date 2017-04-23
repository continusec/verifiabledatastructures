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
	"encoding/json"

	"github.com/continusec/verifiabledatastructures/pb"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LogFetchEntries returns the log entries
func (s *localServiceImpl) LogFetchEntries(ctx context.Context, req *pb.LogFetchEntriesRequest) (*pb.LogFetchEntriesResponse, error) {
	am, err := s.verifyAccessForLogOperation(ctx, req.Log, operationReadEntry)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "no access: %s", err)
	}

	if req.First < 0 || req.Last < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "tree size out of range")
	}

	var rv *pb.LogFetchEntriesResponse
	ns, err := logBucket(req.Log)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "extra getting bucket: %s", err)
	}
	err = s.Reader.ExecuteReadOnly(ctx, ns, func(kr KeyReader) error {
		head, err := lookupLogTreeHead(ctx, kr, req.Log.LogType)
		if err != nil {
			return err
		}

		last := req.Last

		// Do we have it already?
		if last == 0 {
			last = head.TreeSize
		}

		// Are we asking for something silly?
		if last > head.TreeSize || req.First >= last {
			return status.Errorf(codes.InvalidArgument, "tree size out of range")
		}

		hashes, err := lookupLogEntryHashes(ctx, kr, req.Log.LogType, req.First, last)
		if err != nil {
			return err
		}

		vals := make([]*pb.LeafData, len(hashes))
		for i, h := range hashes {
			v, err := lookupDataByLeafHash(ctx, kr, req.Log.LogType, h)
			if err != nil {
				return err
			}

			switch req.Log.LogType {
			case pb.LogType_STRUCT_TYPE_LOG:
				vals[i], err = filterLeafData(v, am)
				if err != nil {
					return err
				}
			case pb.LogType_STRUCT_TYPE_TREEHEAD_LOG:
				vals[i] = v
			case pb.LogType_STRUCT_TYPE_MUTATION_LOG:
				var mm pb.MapMutation
				err = json.Unmarshal(v.ExtraData, &mm)
				if err != nil {
					return err
				}
				mm.Value, err = filterLeafData(mm.Value, am)
				if err != nil {
					return err
				}

				newVal, err := json.Marshal(&mm)
				if err != nil {
					return err
				}

				vals[i] = &pb.LeafData{
					LeafInput: v.LeafInput,
					Format:    v.Format,
					ExtraData: newVal,
				}
			default:
				return status.Errorf(codes.InvalidArgument, "bad log type")
			}
		}

		rv = &pb.LogFetchEntriesResponse{
			Values: vals,
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
