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

func (s *LocalService) applyMapCreate(nsMut NamespaceMutator, db KeyWriter, req *pb.MapCreateRequest) error {
	k := []byte(req.Map.Name)
	_, err := db.Get(mapsBucket, k)
	switch err {
	case nil:
		return ErrLogAlreadyExists
	case ErrNoSuchKey:
	// continue
	default:
		return err
	}

	ns, err := s.mapBucket(req.Map)
	if err != nil {
		return err
	}
	err = nsMut.ResetNamespace(ns, true)
	if err != nil {
		return err
	}

	return s.writeProto(db, mapsBucket, k, &pb.MapInfo{
		Name: req.Map.Name,
	})
}

func (s *LocalService) MapCreate(ctx context.Context, req *pb.MapCreateRequest) (*pb.MapCreateResponse, error) {
	err := s.verifyAccessForMap(req.Map, pb.Permission_PERM_MAP_CREATE)
	if err != nil {
		return nil, err
	}
	if len(req.Map.Name) == 0 {
		return nil, ErrInvalidRequest
	}
	ns, err := s.accountBucket(req.Map.Account)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	promise, err := s.Mutator.QueueMutation(ns, &pb.Mutation{
		MapCreate: req,
	})
	if err != nil {
		return nil, err
	}
	err = promise.WaitUntilDone()
	if err != nil {
		return nil, err
	}
	return &pb.MapCreateResponse{}, nil
}
