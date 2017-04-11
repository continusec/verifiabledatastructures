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
	"encoding/binary"

	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/golang/protobuf/proto"
)

var (
	logHead    = []byte("head") // pb.LogTreeHash
	indexTree  = []byte("root") // followed by uint64 index -> pb.LogTreeHash
	leafPrefix = []byte("leaf") // followed by uint64 index -> pb.LeafNode
	nodePrefix = []byte("node") // followed by uint64 uint64 -> pb.TreeNode
	hashPrefix = []byte("hash") // followed by leaf node hash -> pb.LeafNode
)

func keyForIdx(prefix []byte, i uint64) []byte {
	rv := make([]byte, len(prefix)+8)
	copy(rv, prefix)
	binary.BigEndian.PutUint64(rv[len(prefix):], i)
	return rv
}

func keyForDoubleIdx(prefix []byte, i, j uint64) []byte {
	rv := make([]byte, len(prefix)+8+8)
	copy(rv, prefix)
	binary.BigEndian.PutUint64(rv[len(prefix):], i)
	binary.BigEndian.PutUint64(rv[len(prefix)+8:], j)
	return rv
}

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

type LocalService struct {
	Mutator      MutatorService
	AccessPolicy AuthorizationOracle
	Reader       StorageReader
}

func (s *LocalService) verifyAccessForMap(vmap *pb.MapRef, perm pb.Permission) error {
	return s.AccessPolicy.VerifyAllowed(vmap.Account.Id, vmap.Account.ApiKey, vmap.Name, perm)
}

func (s *LocalService) verifyAccessForLog(log *pb.LogRef, perm pb.Permission) error {
	return s.AccessPolicy.VerifyAllowed(log.Account.Id, log.Account.ApiKey, log.Name, perm)
}

func (s *LocalService) verifyAccessForLogOperation(log *pb.LogRef, op int) error {
	perm, ok := operationForLogType[log.LogType][op]
	if !ok {
		return ErrNotAuthorized
	}

	return s.verifyAccessForLog(log, perm)
}

func entryFormatterForHashableData(hd *pb.HashableData) (client.UploadableEntry, error) {
	switch hd.Format {
	case pb.EntryFormat_ENTRY_FORMAT_RAW:
		return &client.RawDataEntry{RawBytes: hd.Value}, nil
	case pb.EntryFormat_ENTRY_FORMAT_JSON:
		return &client.JsonEntry{JsonBytes: hd.Value}, nil
	case pb.EntryFormat_ENTRY_FORMAT_JSON_REDACTED:
		return &client.RedactableJsonEntry{JsonBytes: hd.Value}, nil
	default:
		return nil, ErrInvalidRequest
	}
}

func (s *LocalService) LogList(ctx context.Context, req *pb.LogListRequest) (*pb.LogListResponse, error) {
	return nil, ErrNotImplemented
}

func (s *LocalService) LogFetchEntries(ctx context.Context, req *pb.LogFetchEntriesRequest) (*pb.LogFetchEntriesResponse, error) {
	err := s.verifyAccessForLogOperation(req.Log, operationReadEntry)
	if err != nil {
		return nil, err
	}
	return nil, ErrNotImplemented
}
func (s *LocalService) LogTreeHash(ctx context.Context, req *pb.LogTreeHashRequest) (*pb.LogTreeHashResponse, error) {
	err := s.verifyAccessForLogOperation(req.Log, operationReadHash)
	if err != nil {
		return nil, err
	}
	/*
		if treeSize < 0 {
			return nil, ErrInvalidTreeRange
		}

		var rv *client.LogTreeHead
		err = l.account.Service.Reader.ExecuteReadOnly(func(kr KeyReader) error {
			head, err := l.getLogTreeHead(kr)
			if err != nil {
				return err
			}

			if treeSize > head.Size {
				return ErrInvalidTreeRange
			} else if treeSize < head.Size {
				head = &pb.LogTreeHash{}
				err = l.readIntoProto(kr, keyForIdx(indexTree, uint64(treeSize)), head)
				if err != nil {
					return err
				}
			} // else, we have the right one, so return it

			rv = &client.LogTreeHead{
				RootHash: head.Hash,
				TreeSize: head.Size,
			}

			return nil
		})
		if err != nil {
			return nil, err
		}

		return rv, nil
	*/
	return nil, ErrNotImplemented
}
func (s *LocalService) LogInclusionProof(ctx context.Context, req *pb.LogInclusionProofRequest) (*pb.LogInclusionProofResponse, error) {
	err := s.verifyAccessForLogOperation(req.Log, operationProveInclusion)
	if err != nil {
		return nil, err
	}
	/*
		if leafIndex < 0 || treeSize < 0 {
			return nil, ErrInvalidTreeRange
		}

		var rv *client.LogInclusionProof
		err = l.account.Service.Reader.ExecuteReadOnly(func(kr KeyReader) error {
			var ln pb.LeafNode
			err := l.readIntoProto(kr, keyForIdx(leafPrefix, uint64(leafIndex)), &ln)
			if err != nil {
				return err
			}
			rv, err = l.inclusionProof(kr, treeSize, &ln)
			return err
		})
		if err != nil {
			return nil, err
		}

		return rv, nil

		head, err := l.getLogTreeHead(kr)
		if err != nil {
			return nil, err
		}

		if treeSize == 0 {
			treeSize = head.Size
		}

		// We technically shouldn't have found it (it may not be completely written yet)
		if ln.Index >= head.Size {
			// we use the NotFound error code so that normal usage of GetInclusionProof, that calls this, returns a uniform error.
			return nil, ErrNotFound
		}

		// Bad input
		if treeSize <= 0 || treeSize > head.Size {
			return nil, ErrInvalidTreeRange
		}

		// Client needs a new STH
		if ln.Index >= treeSize {
			return nil, ErrInvalidTreeRange
		}

		// Ranges are good
		ranges := client.Path(ln.Index, 0, treeSize)
		path, err := l.fetchSubTreeHashes(kr, ranges, false)
		if err != nil {
			return nil, err
		}
		for i, rr := range ranges {
			if len(path[i]) == 0 {
				if client.IsPow2(rr[1] - rr[0]) {
					// Would have been nice if GetSubTreeHashes could better handle these
					return nil, ErrNotFound
				}
				path[i], err = l.calcSubTreeHash(kr, rr[0], rr[1])
				if err != nil {
					return nil, err
				}
			}
		}

		return &client.LogInclusionProof{
			LeafHash:  ln.Mtl,
			LeafIndex: ln.Index,
			TreeSize:  treeSize,
			AuditPath: path,
		}, nil

		err := l.verifyAccessForOperation(operationProveInclusion)
		if err != nil {
			return nil, err
		}

		if treeSize < 0 {
			return nil, ErrInvalidTreeRange
		}

		lh, err := leaf.LeafHash()
		if err != nil {
			return nil, err
		}
		key := append(hashPrefix, lh...)

		var rv *client.LogInclusionProof
		err = l.account.Service.Reader.ExecuteReadOnly(func(kr KeyReader) error {
			var ln pb.LeafNode
			err := l.readIntoProto(kr, key, &ln)
			if err != nil {
				return err
			}
			rv, err = l.inclusionProof(kr, treeSize, &ln)
			return err
		})
		if err != nil {
			return nil, err
		}

		return rv, nil
	*/
	return nil, ErrNotImplemented
}
func (s *LocalService) LogConsistencyProof(ctx context.Context, req *pb.LogConsistencyProofRequest) (*pb.LogConsistencyProofResponse, error) {
	err := s.verifyAccessForLogOperation(req.Log, operationReadHash)
	if err != nil {
		return nil, err
	}
	/*
		if first <= 0 {
			return nil, ErrInvalidTreeRange
		}

		if second < 0 { // we allow zero for second param
			return nil, ErrInvalidTreeRange
		}

		var rv *client.LogConsistencyProof
		err = l.account.Service.Reader.ExecuteReadOnly(func(kr KeyReader) error {
			head, err := l.getLogTreeHead(kr)
			if err != nil {
				return err
			}

			if second == 0 {
				second = head.Size
			}

			if second <= 0 || second > head.Size {
				return ErrInvalidTreeRange
			}
			if first >= second {
				return ErrInvalidTreeRange
			}

			// Ranges are good
			ranges := client.SubProof(first, 0, second, true)
			path, err := l.fetchSubTreeHashes(kr, ranges, false)
			if err != nil {
				return err
			}
			for i, rr := range ranges {
				if len(path[i]) == 0 {
					if client.IsPow2(rr[1] - rr[0]) {
						// Would have been nice if GetSubTreeHashes could better handle these
						return ErrNoSuchKey
					}
					path[i], err = l.calcSubTreeHash(kr, rr[0], rr[1])
					if err != nil {
						return err
					}
				}
			}
			rv = &client.LogConsistencyProof{
				FirstSize:  first,
				SecondSize: second,
				AuditPath:  path,
			}
			return nil
		})

		return rv, nil*/
	return nil, ErrNotImplemented
}
func (s *LocalService) MapCreate(ctx context.Context, req *pb.MapCreateRequest) (*pb.MapCreateResponse, error) {
	err := s.verifyAccessForMap(req.Map, pb.Permission_PERM_MAP_CREATE)
	if err != nil {
		return nil, err
	} /*
		if len(m.name) == 0 {
			return nil, ErrInvalidRequest
		}
		promise, err := m.account.Service.Mutator.QueueMutation(&pb.Mutation{
			Account:   m.account.Account,
			Name:      m.name,
			Operation: pb.MutationType_MUT_MAP_CREATE,
		})
		if err != nil {
			return nil, err
		}
		return promise.WaitUntilDone()*/
	return nil, ErrNotImplemented
}
func (s *LocalService) MapDelete(ctx context.Context, req *pb.MapDeleteRequest) (*pb.MapDeleteResponse, error) {
	err := s.verifyAccessForMap(req.Map, pb.Permission_PERM_MAP_DELETE)
	if err != nil {
		return nil, err
	} /*
		promise, err := m.account.Service.Mutator.QueueMutation(&pb.Mutation{
			Account:   m.account.Account,
			Name:      m.name,
			Operation: pb.MutationType_MUT_MAP_DESTROY,
		})
		if err != nil {
			return nil, err
		}
		return promise.WaitUntilDone()*/

	return nil, ErrNotImplemented
}
func (s *LocalService) MapList(ctx context.Context, req *pb.MapListRequest) (*pb.MapListResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) MapSetValue(ctx context.Context, req *pb.MapSetValueRequest) (*pb.MapSetValueResponse, error) {
	err := s.verifyAccessForMap(req.Map, pb.Permission_PERM_MAP_SET_VALUE)
	if err != nil {
		return nil, err
	}
	return nil, ErrNotImplemented
}
func (s *LocalService) MapGetValue(ctx context.Context, req *pb.MapGetValueRequest) (*pb.MapGetValueResponse, error) {
	err := s.verifyAccessForMap(req.Map, pb.Permission_PERM_MAP_GET_VALUE)
	if err != nil {
		return nil, err
	}

	return nil, ErrNotImplemented
}
func (s *LocalService) MapTreeHash(ctx context.Context, req *pb.MapTreeHashRequest) (*pb.MapTreeHashResponse, error) {
	err := s.verifyAccessForMap(req.Map, pb.Permission_PERM_MAP_GET_VALUE)
	if err != nil {
		return nil, err
	}

	return nil, ErrNotImplemented
}

/* MUST be pow2. Assumes all args are range checked first */
/* Actually, the above is a lie. If failOnMissing is set, then we fail if any values are missing.
   Otherwise we will return nil in those spots and return what we can. */
func (l *LocalService) fetchSubTreeHashes(kr KeyReader, ranges [][2]int64, failOnMissing bool) ([][]byte, error) {
	/*
		Deliberately do not always error check above, as we wish to allow
		for some empty nodes, e.g. 4..7. These must be picked up by
		the caller
	*/
	rv := make([][]byte, len(ranges))
	for i, r := range ranges {
		if (r[1] - r[0]) == 1 {
			var m pb.LeafNode
			err := l.readIntoProto(kr, keyForIdx(leafPrefix, uint64(r[0])), &m)
			if err == nil {
				rv[i] = m.Mtl
			} else {
				if failOnMissing {
					return nil, err
				}
			}
		} else {
			var m pb.TreeNode
			err := l.readIntoProto(kr, keyForDoubleIdx(nodePrefix, uint64(r[0]), uint64(r[1])), &m)
			if err == nil {
				rv[i] = m.Mth
			} else {
				if failOnMissing {
					return nil, err
				}
			}
		}
	}

	return rv, nil
}

/* Assumes all args are range checked first */
func (l *LocalService) calcSubTreeHash(kr KeyReader, start, end int64) ([]byte, error) {
	r := make([][2]int64, 0, 8) // magic number bad - why did we do this?

	for start != end {
		k := client.CalcK((end - start) + 1)
		r = append(r, [2]int64{start, start + k})
		start += k
	}

	hashes, err := l.fetchSubTreeHashes(kr, r, true)
	if err != nil {
		return nil, err
	}

	if len(hashes) == 0 {
		return nil, ErrInvalidTreeRange
	}

	rv := hashes[len(hashes)-1]
	for i := len(hashes) - 2; i >= 0; i-- {
		rv = client.NodeMerkleTreeHash(hashes[i], rv)
	}

	return rv, nil
}

func (l *LocalService) getLogTreeHead(kr KeyReader) (*pb.LogTreeHash, error) {
	var lth pb.LogTreeHash
	err := l.readIntoProto(kr, logHead, &lth)
	switch err {
	case nil:
		return &lth, nil
	case ErrNoSuchKey:
		lth.Reset() // 0, nil
		return &lth, nil
	default:
		return nil, err
	}
}

func (l *LocalService) readIntoProto(kr KeyReader, key []byte, m proto.Message) error {
	bucket, err := l.bucket()
	if err != nil {
		return err
	}

	val, err := kr.Get(bucket, key)
	if err != nil {
		return err
	}

	return proto.Unmarshal(val, m)
}

func (l *LocalService) bucket() ([]byte, error) {
	return nil, ErrNotImplemented // TODO
	/*
		if l.bucketKey == nil {
			var err error
			l.bucketKey, err = objecthash.ObjectHash(map[string]interface{}{
				"account": l.account.Account,
				"name":    l.name,
				"type":    l.logType,
			})
			if err != nil {
				return nil, err
			}
		}
		return l.bucketKey, nil*/
}
