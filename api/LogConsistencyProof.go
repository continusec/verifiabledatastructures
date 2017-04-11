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

func (s *LocalService) LogConsistencyProof(ctx context.Context, req *pb.LogConsistencyProofRequest) (*pb.LogConsistencyProofResponse, error) {
	err := s.verifyAccessForLogOperation(req.Log, operationReadHash)
	if err != nil {
		return nil, err
	}

	if req.FromSize <= 0 {
		return nil, ErrInvalidTreeRange
	}

	if req.TreeSize < 0 { // we allow zero for second param
		return nil, ErrInvalidTreeRange
	}

	var rv *pb.LogConsistencyProofResponse
	err = s.Reader.ExecuteReadOnly(func(kr KeyReader) error {
		head, err := s.getLogTreeHead(kr, req.Log)
		if err != nil {
			return err
		}
		second := req.TreeSize
		if second == 0 {
			second = head.TreeSize
		}

		if second <= 0 || second > head.TreeSize {
			return ErrInvalidTreeRange
		}
		if req.FromSize >= second {
			return ErrInvalidTreeRange
		}

		// Ranges are good
		ranges := client.SubProof(req.FromSize, 0, second, true)
		path, err := s.fetchSubTreeHashes(kr, req.Log, ranges, false)
		if err != nil {
			return err
		}
		for i, rr := range ranges {
			if len(path[i]) == 0 {
				if client.IsPow2(rr[1] - rr[0]) {
					// Would have been nice if GetSubTreeHashes could better handle these
					return ErrNoSuchKey
				}
				path[i], err = s.calcSubTreeHash(kr, req.Log, rr[0], rr[1])
				if err != nil {
					return err
				}
			}
		}
		rv = &pb.LogConsistencyProofResponse{
			FromSize:  req.FromSize,
			TreeSize:  second,
			AuditPath: path,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rv, nil
}
