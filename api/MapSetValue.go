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
	"encoding/json"

	"golang.org/x/net/context"

	"github.com/continusec/objecthash"
	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/pb"
)

func jsonObjectHash(orig interface{}) ([]byte, error) {
	// First we marshal it to JSON form
	ob, err := json.Marshal(orig)
	if err != nil {
		return ob, err
	}

	var o interface{}
	err = json.Unmarshal(ob, &o)
	if err != nil {
		return nil, err
	}

	return objecthash.ObjectHash(o)
}

func makeJSONMutationEntry(req *pb.MapSetValueRequest) (*client.JSONMapMutationEntry, error) {
	rv := &client.JSONMapMutationEntry{Key: req.Key}
	if req.Action == pb.MapMutationAction_MAP_MUTATION_DELETE {
		rv.Action = "delete"
		return rv, nil
	}

	rv.Value = client.LeafMerkleTreeHash(req.Value.LeafInput)

	switch req.Action {
	case pb.MapMutationAction_MAP_MUTATION_SET:
		rv.Action = "set"
		return rv, nil
	case pb.MapMutationAction_MAP_MUTATION_UPDATE:
		rv.Action = "update"
		rv.PreviousLeafHash = req.PrevLeafHash
		return rv, nil
	default:
		return nil, ErrInvalidRequest
	}
}

func (s *LocalService) MapSetValue(ctx context.Context, req *pb.MapSetValueRequest) (*pb.MapSetValueResponse, error) {
	err := s.verifyAccessForMap(req.Map, pb.Permission_PERM_MAP_SET_VALUE)
	if err != nil {
		return nil, err
	}

	mm, err := makeJSONMutationEntry(req)
	if err != nil {
		return nil, ErrInvalidRequest
	}

	leafInput, err := jsonObjectHash(mm)
	if err != nil {
		return nil, err
	}

	_, err = s.Mutator.QueueMutation(&pb.Mutation{
		MapSetValue: req,
	})
	if err != nil {
		return nil, err
	}
	return &pb.MapSetValueResponse{
		LeafHash: client.LeafMerkleTreeHash(leafInput),
	}, nil
}
