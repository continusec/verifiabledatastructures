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

	"github.com/continusec/objecthash"
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

/* MUST be pow2. Assumes all args are range checked first */
/* Actually, the above is a lie. If failOnMissing is set, then we fail if any values are missing.
   Otherwise we will return nil in those spots and return what we can. */
func (l *LocalService) fetchSubTreeHashes(kr KeyReader, log *pb.LogRef, ranges [][2]int64, failOnMissing bool) ([][]byte, error) {
	/*
		Deliberately do not always error check above, as we wish to allow
		for some empty nodes, e.g. 4..7. These must be picked up by
		the caller
	*/
	rv := make([][]byte, len(ranges))
	for i, r := range ranges {
		if (r[1] - r[0]) == 1 {
			var m pb.LeafNode
			err := l.readIntoProto(kr, log, keyForIdx(leafPrefix, uint64(r[0])), &m)
			if err == nil {
				rv[i] = m.Mth
			} else {
				if failOnMissing {
					return nil, err
				}
			}
		} else {
			var m pb.TreeNode
			err := l.readIntoProto(kr, log, keyForDoubleIdx(nodePrefix, uint64(r[0]), uint64(r[1])), &m)
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
func (l *LocalService) calcSubTreeHash(kr KeyReader, log *pb.LogRef, start, end int64) ([]byte, error) {
	r := make([][2]int64, 0, 8) // magic number bad - why did we do this?

	for start != end {
		k := client.CalcK((end - start) + 1)
		r = append(r, [2]int64{start, start + k})
		start += k
	}

	hashes, err := l.fetchSubTreeHashes(kr, log, r, true)
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

func (l *LocalService) getLogTreeHead(kr KeyReader, log *pb.LogRef) (*pb.LogTreeHashResponse, error) {
	var lth pb.LogTreeHashResponse
	err := l.readIntoProto(kr, log, logHead, &lth)
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

func (l *LocalService) readIntoProto(kr KeyReader, log *pb.LogRef, key []byte, m proto.Message) error {
	bucket, err := l.bucket(log)
	if err != nil {
		return err
	}

	val, err := kr.Get(bucket, key)
	if err != nil {
		return err
	}

	return proto.Unmarshal(val, m)
}

func (l *LocalService) bucket(log *pb.LogRef) ([]byte, error) {
	// TODO, cache this
	return objecthash.ObjectHash(map[string]interface{}{
		"account": log.Account.Id,
		"name":    log.Name,
		"type":    log.LogType,
	})
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
