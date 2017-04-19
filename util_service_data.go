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
	"encoding/binary"

	"github.com/continusec/objecthash"
)

const (
	dataByLeafHash  = 0
	leafNodeByIndex = 1
	treeNodeByRange = 2
	rootHashBySize  = 3
	indexByLeafHash = 4
)

func generateBucketNames() map[int]map[LogType][]byte {
	rv := make(map[int]map[LogType][]byte)
	for _, b := range []struct {
		BucketType int
		Suffix     string
	}{
		{BucketType: dataByLeafHash, Suffix: "data"},
		{BucketType: leafNodeByIndex, Suffix: "leaf"},
		{BucketType: treeNodeByRange, Suffix: "node"},
		{BucketType: rootHashBySize, Suffix: "tree"},
		{BucketType: indexByLeafHash, Suffix: "index"},
	} {
		rv[b.BucketType] = make(map[LogType][]byte)
		for _, lt := range []struct {
			LogType LogType
			Prefix  string
		}{
			{LogType: LogType_STRUCT_TYPE_LOG, Prefix: "user"},
			{LogType: LogType_STRUCT_TYPE_MUTATION_LOG, Prefix: "mutation"},
			{LogType: LogType_STRUCT_TYPE_TREEHEAD_LOG, Prefix: "treehead"},
		} {
			rv[b.BucketType][lt.LogType] = []byte(lt.Prefix + "_" + b.Suffix)
		}
	}
	return rv
}

var (
	buckets = generateBucketNames()

	objSizeKey    = []byte("size")
	mapNodeBucket = []byte("map_node")
	metadata      = []byte("metadata")
)

// Start pair

func writeDataByLeafHash(kr KeyWriter, lt LogType, lh []byte, data *LeafData) error {
	return kr.Set(buckets[dataByLeafHash][lt], lh, data)
}

func lookupDataByLeafHash(kr KeyReader, lt LogType, lh []byte) (*LeafData, error) {
	var m LeafData
	err := kr.Get(buckets[dataByLeafHash][lt], lh, &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func writeLeafNodeByIndex(kr KeyWriter, lt LogType, idx int64, data *LeafNode) error {
	return kr.Set(buckets[leafNodeByIndex][lt], toIntBinary(uint64(idx)), data)
}

func lookupLeafNodeByIndex(kr KeyReader, lt LogType, idx int64) (*LeafNode, error) {
	var m LeafNode
	err := kr.Get(buckets[leafNodeByIndex][lt], toIntBinary(uint64(idx)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func writeTreeNodeByRange(kr KeyWriter, lt LogType, a, b int64, data *TreeNode) error {
	return kr.Set(buckets[treeNodeByRange][lt], toDoubleIntBinary(uint64(a), uint64(b)), data)
}

func lookupTreeNodeByRange(kr KeyReader, lt LogType, a, b int64) (*TreeNode, error) {
	var m TreeNode
	err := kr.Get(buckets[treeNodeByRange][lt], toDoubleIntBinary(uint64(a), uint64(b)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func writeLogRootHashBySize(kr KeyWriter, lt LogType, size int64, data *LogTreeHash) error {
	return kr.Set(buckets[rootHashBySize][lt], toIntBinary(uint64(size)), data)
}

// size must be > 0
func lookupLogRootHashBySize(kr KeyReader, lt LogType, size int64) (*LogTreeHash, error) {
	var m LogTreeHash
	err := kr.Get(buckets[rootHashBySize][lt], toIntBinary(uint64(size)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func writeIndexByLeafHash(kr KeyWriter, lt LogType, lh []byte, data *EntryIndex) error {
	return kr.Set(buckets[indexByLeafHash][lt], lh, data)
}

func lookupIndexByLeafHash(kr KeyReader, lt LogType, lh []byte) (*EntryIndex, error) {
	var m EntryIndex
	err := kr.Get(buckets[indexByLeafHash][lt], lh, &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func writeObjectSize(kr KeyWriter, size int64) error {
	return kr.Set(metadata, objSizeKey, &ObjectSize{Size: size})
}

func readObjectSize(kr KeyReader) (int64, error) {
	var lth ObjectSize
	err := kr.Get(metadata, objSizeKey, &lth)
	switch err {
	case nil:
		return lth.Size, nil
	case ErrNoSuchKey:
		return 0, nil
	default:
		return 0, err
	}
}

func lookupLogTreeHead(kr KeyReader, lt LogType) (*LogTreeHashResponse, error) {
	objectSize, err := readObjectSize(kr)
	if err != nil {
		return nil, err
	}
	if objectSize == 0 {
		return &LogTreeHashResponse{}, nil // zero-ed out
	}

	lth, err := lookupLogRootHashBySize(kr, lt, objectSize)
	if err != nil {
		return nil, err
	}

	return &LogTreeHashResponse{
		RootHash: lth.Mth,
		TreeSize: objectSize,
	}, nil
}

// Start pair

func writeMapHash(kr KeyWriter, number int64, path BPath, data *MapNode) error {
	return kr.Set(mapNodeBucket, append(toIntBinary(uint64(number)), path...), data)
}

func lookupMapHash(kr KeyReader, number int64, path BPath) (*MapNode, error) {
	// Special case 0
	if number == 0 && path.Length() == 0 {
		return &MapNode{}, nil
	}
	var m MapNode
	err := kr.Get(mapNodeBucket, append(toIntBinary(uint64(number)), path...), &m)
	if err != nil {
		return nil, err
	}

	return &m, nil
}

// End pairs

func lookupLogEntryHashes(kr KeyReader, lt LogType, first, last int64) ([][]byte, error) {
	rv := make([][]byte, last-first)
	for i := first; i < last; i++ { // if we add a range / scan operation to KeyReader, this could be quicker
		x, err := lookupLeafNodeByIndex(kr, lt, i)
		if err != nil {
			return nil, err
		}
		rv[i-first] = x.Mth
	}
	return rv, nil
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

func logBucket(log *LogRef) ([]byte, error) {
	if log.LogType == LogType_STRUCT_TYPE_LOG {
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

func mapBucket(vmap *MapRef) ([]byte, error) {
	return objecthash.ObjectHash(map[string]interface{}{
		"account": vmap.Account.Id,
		"name":    vmap.Name,
		"type":    "map",
	})
}
