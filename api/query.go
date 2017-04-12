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
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/golang/protobuf/proto"
)

var (
	logsPrefix = []byte("logs") // pb.LogInfo
	mapsPrefix = []byte("maps") // pb.MapInfo

	headPrefix = []byte("head") // pb.LogTreeHash
	leafPrefix = []byte("leaf") // followed by uint64 index -> pb.LeafNode
	nodePrefix = []byte("node") // followed by uint64 uint64 -> pb.TreeNode
	rootPrefix = []byte("root") // followed by uint64 index -> pb.LogTreeHash
	hashPrefix = []byte("hash") // followed by []byte hash -> pb.LogTreeHash
)

func (l *LocalService) lookupLeafNodeByIndex(kr KeyReader, log *pb.LogRef, idx int64) (*pb.LeafNode, error) {
	var m pb.LeafNode
	err := l.readIntoProto(kr, log, keyForIdx(leafPrefix, uint64(idx)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (l *LocalService) lookupTreeNodeByRange(kr KeyReader, log *pb.LogRef, a, b int64) (*pb.TreeNode, error) {
	var m pb.TreeNode
	err := l.readIntoProto(kr, log, keyForDoubleIdx(nodePrefix, uint64(a), uint64(b)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// size must be > 0
func (l *LocalService) lookupLogRootHashBySize(kr KeyReader, log *pb.LogRef, size int64) (*pb.LogTreeHash, error) {
	var m pb.LogTreeHash
	err := l.readIntoProto(kr, log, keyForIdx(rootPrefix, uint64(size)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (l *LocalService) lookupIndexByLeafHash(kr KeyReader, log *pb.LogRef, lh []byte) (*pb.EntryIndex, error) {
	var m pb.EntryIndex
	err := l.readIntoProto(kr, log, append(hashPrefix, lh...), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (l *LocalService) lookupLogTreeHead(kr KeyReader, log *pb.LogRef) (*pb.LogTreeHashResponse, error) {
	var lth pb.LogTreeHashResponse
	err := l.readIntoProto(kr, log, headPrefix, &lth)
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

func (l *LocalService) lookupAccountLogs(kr KeyReader, acc *pb.AccountRef) ([]*pb.LogInfo, error) {
	bucket, err := l.accountBucket(acc)
	if err != nil {
		return nil, err
	}
	result, err := kr.Scan(bucket, logsPrefix)
	if err != nil {
		return nil, err
	}
	rv := make([]*pb.LogInfo, len(result))
	for i, row := range result {
		var li pb.LogInfo
		err = proto.Unmarshal(row[1], &li)
		if err != nil {
			return nil, err
		}
		rv[i] = &li
	}
	return rv, nil
}

func (l *LocalService) lookupAccountMaps(kr KeyReader, acc *pb.AccountRef) ([]*pb.MapInfo, error) {
	bucket, err := l.accountBucket(acc)
	if err != nil {
		return nil, err
	}
	result, err := kr.Scan(bucket, mapsPrefix)
	if err != nil {
		return nil, err
	}
	rv := make([]*pb.MapInfo, len(result))
	for i, row := range result {
		var li pb.MapInfo
		err = proto.Unmarshal(row[1], &li)
		if err != nil {
			return nil, err
		}
		rv[i] = &li
	}
	return rv, nil
}

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

func (l *LocalService) accountBucket(account *pb.AccountRef) ([]byte, error) {
	// TODO, cache this
	return objecthash.ObjectHash(map[string]interface{}{
		"account": account.Id,
	})
}
