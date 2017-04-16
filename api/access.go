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

	"github.com/continusec/objecthash"
	"github.com/continusec/verifiabledatastructures/pb"
)

const (
	operationRawAdd         = 1
	operationReadEntry      = 2
	operationReadHash       = 3
	operationProveInclusion = 4
)

var (
	operationForLogType = map[pb.LogType]map[int]pb.Permission{
		pb.LogType_STRUCT_TYPE_LOG: map[int]pb.Permission{
			operationRawAdd:         pb.Permission_PERM_LOG_RAW_ADD,
			operationReadEntry:      pb.Permission_PERM_LOG_READ_ENTRY,
			operationReadHash:       pb.Permission_PERM_LOG_READ_HASH,
			operationProveInclusion: pb.Permission_PERM_LOG_PROVE_INCLUSION,
		},
		pb.LogType_STRUCT_TYPE_MUTATION_LOG: map[int]pb.Permission{ // This is not a typo, we deliberately consider read entries of mutation log as separate and sensitive.
			operationReadEntry:      pb.Permission_PERM_MAP_MUTATION_READ_ENTRY,
			operationReadHash:       pb.Permission_PERM_MAP_MUTATION_READ_HASH,
			operationProveInclusion: pb.Permission_PERM_MAP_MUTATION_READ_HASH,
		},
		pb.LogType_STRUCT_TYPE_TREEHEAD_LOG: map[int]pb.Permission{
			operationReadEntry:      pb.Permission_PERM_MAP_MUTATION_READ_HASH,
			operationReadHash:       pb.Permission_PERM_MAP_MUTATION_READ_HASH,
			operationProveInclusion: pb.Permission_PERM_MAP_MUTATION_READ_HASH,
		},
	}
)

func (s *LocalService) verifyAccessForMap(vmap *pb.MapRef, perm pb.Permission) (*AccessModifier, error) {
	return s.AccessPolicy.VerifyAllowed(vmap.Account.Id, vmap.Account.ApiKey, vmap.Name, perm)
}

func (s *LocalService) verifyAccessForLog(log *pb.LogRef, perm pb.Permission) (*AccessModifier, error) {
	return s.AccessPolicy.VerifyAllowed(log.Account.Id, log.Account.ApiKey, log.Name, perm)
}

func (s *LocalService) verifyAccessForLogOperation(log *pb.LogRef, op int) (*AccessModifier, error) {
	perm, ok := operationForLogType[log.LogType][op]
	if !ok {
		return nil, ErrNotAuthorized
	}

	return s.verifyAccessForLog(log, perm)
}

func filterLeafData(ld *pb.LeafData, am *AccessModifier) (*pb.LeafData, error) {
	switch ld.Format {
	case pb.DataFormat_UNSPECIFIED:
		return ld, nil
	case pb.DataFormat_JSON:
		if am.FieldFilter == AllFields {
			return ld, nil
		}
		var o interface{}
		err := json.Unmarshal(ld.ExtraData, &o)
		if err != nil {
			return nil, ErrInvalidJSON
		}
		o, err = objecthash.Filtered(o, am.FieldFilter)
		if err != nil {
			return nil, err
		}
		rv, err := json.Marshal(o)
		if err != nil {
			return nil, err
		}
		return &pb.LeafData{
			LeafInput: ld.LeafInput,
			ExtraData: rv, // redacted form
		}, nil
	default:
		return nil, ErrInvalidRequest
	}

}
