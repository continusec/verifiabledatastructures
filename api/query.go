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
)

const (
	dataByLeafHash  = 0
	leafNodeByIndex = 1
	treeNodeByRange = 2
	rootHashBySize  = 3
	indexByLeafHash = 4
	metadata        = 5
)

func generateBucketNames() map[int]map[pb.LogType][]byte {
	rv := make(map[int]map[pb.LogType][]byte)
	for _, b := range []struct {
		BucketType int
		Suffix     string
	}{
		{BucketType: dataByLeafHash, Suffix: "data"},
		{BucketType: leafNodeByIndex, Suffix: "leaf"},
		{BucketType: treeNodeByRange, Suffix: "node"},
		{BucketType: rootHashBySize, Suffix: "tree"},
		{BucketType: indexByLeafHash, Suffix: "index"},
		{BucketType: metadata, Suffix: "metadata"},
	} {
		rv[b.BucketType] = make(map[pb.LogType][]byte)
		for _, lt := range []struct {
			LogType pb.LogType
			Prefix  string
		}{
			{LogType: pb.LogType_STRUCT_TYPE_LOG, Prefix: "user"},
			{LogType: pb.LogType_STRUCT_TYPE_MUTATION_LOG, Prefix: "mutation"},
			{LogType: pb.LogType_STRUCT_TYPE_TREEHEAD_LOG, Prefix: "treehead"},
		} {
			rv[b.BucketType][lt.LogType] = []byte(lt.Prefix + "_" + b.Suffix)
		}
	}
	return rv
}

var (
	buckets = generateBucketNames()

	headKey       = []byte("head")
	mapsBucket    = []byte("maps")
	logsBucket    = []byte("logs")
	mapNodeBucket = []byte("map_node")
)

// Start pair

func (l *LocalService) writeDataByLeafHash(kr KeyWriter, lt pb.LogType, lh []byte, data *pb.LeafData) error {
	return kr.Set(buckets[dataByLeafHash][lt], lh, data)
}

func (l *LocalService) lookupDataByLeafHash(kr KeyReader, lt pb.LogType, lh []byte) (*pb.LeafData, error) {
	var m pb.LeafData
	err := kr.Get(buckets[dataByLeafHash][lt], lh, &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func (l *LocalService) writeLeafNodeByIndex(kr KeyWriter, lt pb.LogType, idx int64, data *pb.LeafNode) error {
	return kr.Set(buckets[leafNodeByIndex][lt], toIntBinary(uint64(idx)), data)
}

func (l *LocalService) lookupLeafNodeByIndex(kr KeyReader, lt pb.LogType, idx int64) (*pb.LeafNode, error) {
	var m pb.LeafNode
	err := kr.Get(buckets[leafNodeByIndex][lt], toIntBinary(uint64(idx)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func (l *LocalService) writeTreeNodeByRange(kr KeyWriter, lt pb.LogType, a, b int64, data *pb.TreeNode) error {
	return kr.Set(buckets[treeNodeByRange][lt], toDoubleIntBinary(uint64(a), uint64(b)), data)
}

func (l *LocalService) lookupTreeNodeByRange(kr KeyReader, lt pb.LogType, a, b int64) (*pb.TreeNode, error) {
	var m pb.TreeNode
	err := kr.Get(buckets[treeNodeByRange][lt], toDoubleIntBinary(uint64(a), uint64(b)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func (l *LocalService) writeLogRootHashBySize(kr KeyWriter, lt pb.LogType, size int64, data *pb.LogTreeHash) error {
	return kr.Set(buckets[rootHashBySize][lt], toIntBinary(uint64(size)), data)
}

// size must be > 0
func (l *LocalService) lookupLogRootHashBySize(kr KeyReader, lt pb.LogType, size int64) (*pb.LogTreeHash, error) {
	var m pb.LogTreeHash
	err := kr.Get(buckets[rootHashBySize][lt], toIntBinary(uint64(size)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func (l *LocalService) writeIndexByLeafHash(kr KeyWriter, lt pb.LogType, lh []byte, data *pb.EntryIndex) error {
	return kr.Set(buckets[indexByLeafHash][lt], lh, data)
}

func (l *LocalService) lookupIndexByLeafHash(kr KeyReader, lt pb.LogType, lh []byte) (*pb.EntryIndex, error) {
	var m pb.EntryIndex
	err := kr.Get(buckets[indexByLeafHash][lt], lh, &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func (l *LocalService) writeLogTreeHead(kr KeyWriter, lt pb.LogType, data *pb.LogTreeHashResponse) error {
	return kr.Set(buckets[metadata][lt], headKey, data)
}

func (l *LocalService) lookupLogTreeHead(kr KeyReader, lt pb.LogType) (*pb.LogTreeHashResponse, error) {
	var lth pb.LogTreeHashResponse
	err := kr.Get(buckets[metadata][lt], headKey, &lth)
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

// Start pair

func (l *LocalService) writeMapHash(kr KeyWriter, number int64, path []byte, data *pb.MapNode) error {
	return kr.Set(mapNodeBucket, append(toIntBinary(uint64(number)), path...), data)
}

func (l *LocalService) lookupMapHash(kr KeyReader, number int64, path []byte) (*pb.MapNode, error) {
	// Special case 0
	if number == 0 && len(path) == 0 {
		return &pb.MapNode{}, nil
	}
	var m pb.MapNode
	err := kr.Get(mapNodeBucket, append(toIntBinary(uint64(number)), path...), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// End pairs

func (l *LocalService) lookupLogEntryHashes(kr KeyReader, lt pb.LogType, first, last int64) ([][]byte, error) {
	rv := make([][]byte, last-first)
	for i := first; i < last; i++ { // if we add a range / scan operation to KeyReader, this could be quicker
		x, err := l.lookupLeafNodeByIndex(kr, lt, i)
		if err != nil {
			return nil, err
		}
		rv[i-first] = x.Mth
	}
	return rv, nil
}

func keyForIdx(prefix []byte, i uint64) []byte {
	rv := make([]byte, len(prefix)+8)
	copy(rv, prefix)
	binary.BigEndian.PutUint64(rv[len(prefix):], i)
	return rv
}

func toIntBinary(i uint64) []byte {
	rv := make([]byte, 8)
	binary.BigEndian.PutUint64(rv, i)
	return rv
}

func toDoubleIntBinary(i, j uint64) []byte {
	rv := make([]byte, 16)
	binary.BigEndian.PutUint64(rv, i)
	binary.BigEndian.PutUint64(rv[8:], j)
	return rv
}

func (l *LocalService) logBucket(log *pb.LogRef) ([]byte, error) {
	if log.LogType == pb.LogType_STRUCT_TYPE_LOG {
		return objecthash.ObjectHash(map[string]interface{}{
			"account": log.Account.Id,
			"name":    log.Name,
			"type":    "log",
		})
	}
	// else, we pretend to be the map
	return objecthash.ObjectHash(map[string]interface{}{
		"account": log.Account.Id,
		"name":    log.Name,
		"type":    "map",
	})
}

func (l *LocalService) mapBucket(vmap *pb.MapRef) ([]byte, error) {
	return objecthash.ObjectHash(map[string]interface{}{
		"account": vmap.Account.Id,
		"name":    vmap.Name,
		"type":    "map",
	})
}
