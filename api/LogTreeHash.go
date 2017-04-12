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

func (s *LocalService) LogTreeHash(ctx context.Context, req *pb.LogTreeHashRequest) (*pb.LogTreeHashResponse, error) {
	err := s.verifyAccessForLogOperation(req.Log, operationReadHash)
	if err != nil {
		return nil, err
	}

	if req.TreeSize < 0 {
		return nil, ErrInvalidTreeRange
	}

	var rv *pb.LogTreeHashResponse
	err = s.Reader.ExecuteReadOnly(func(kr KeyReader) error {
		head, err := s.lookupLogTreeHead(kr, req.Log)
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
			return ErrInvalidTreeRange
		}

		m, err := s.lookupLogRootHashBySize(kr, req.Log, req.TreeSize)
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
		return nil, err
	}

	return rv, nil
}
