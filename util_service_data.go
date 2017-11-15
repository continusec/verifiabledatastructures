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

	"github.com/continusec/verifiabledatastructures/pb"
	"golang.org/x/net/context"

	"github.com/continusec/objecthash"
	"github.com/continusec/verifiabledatastructures/util"
)

const (
	dataByLeafHash  = 0
	leafNodeByIndex = 1
	treeNodeByRange = 2
	rootHashBySize  = 3
	indexByLeafHash = 4
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

	objSizeKey    = []byte("size")
	mapNodeBucket = []byte("map_node")
	metadata      = []byte("metadata")
)

// Start pair

func writeDataByLeafHash(ctx context.Context, kr KeyWriter, lt pb.LogType, lh []byte, data *pb.LeafData) error {
	return kr.Set(ctx, buckets[dataByLeafHash][lt], lh, data)
}

func lookupDataByLeafHash(ctx context.Context, kr KeyReader, lt pb.LogType, lh []byte) (*pb.LeafData, error) {
	var m pb.LeafData
	err := kr.Get(ctx, buckets[dataByLeafHash][lt], lh, &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func writeLeafNodeByIndex(ctx context.Context, kr KeyWriter, lt pb.LogType, idx int64, data *pb.LeafNode) error {
	return kr.Set(ctx, buckets[leafNodeByIndex][lt], toIntBinary(uint64(idx)), data)
}

func lookupLeafNodeByIndex(ctx context.Context, kr KeyReader, lt pb.LogType, idx int64) (*pb.LeafNode, error) {
	var m pb.LeafNode
	err := kr.Get(ctx, buckets[leafNodeByIndex][lt], toIntBinary(uint64(idx)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func writeTreeNodeByRange(ctx context.Context, kr KeyWriter, lt pb.LogType, a, b int64, data *pb.TreeNode) error {
	return kr.Set(ctx, buckets[treeNodeByRange][lt], toDoubleIntBinary(uint64(a), uint64(b)), data)
}

func lookupTreeNodeByRange(ctx context.Context, kr KeyReader, lt pb.LogType, a, b int64) (*pb.TreeNode, error) {
	var m pb.TreeNode
	err := kr.Get(ctx, buckets[treeNodeByRange][lt], toDoubleIntBinary(uint64(a), uint64(b)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func writeLogRootHashBySize(ctx context.Context, kr KeyWriter, lt pb.LogType, size int64, data *pb.LogTreeHash) error {
	return kr.Set(ctx, buckets[rootHashBySize][lt], toIntBinary(uint64(size)), data)
}

// size must be > 0
func lookupLogRootHashBySize(ctx context.Context, kr KeyReader, lt pb.LogType, size int64) (*pb.LogTreeHash, error) {
	var m pb.LogTreeHash
	err := kr.Get(ctx, buckets[rootHashBySize][lt], toIntBinary(uint64(size)), &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func writeIndexByLeafHash(ctx context.Context, kr KeyWriter, lt pb.LogType, lh []byte, data *pb.EntryIndex) error {
	return kr.Set(ctx, buckets[indexByLeafHash][lt], lh, data)
}

func lookupIndexByLeafHash(ctx context.Context, kr KeyReader, lt pb.LogType, lh []byte) (*pb.EntryIndex, error) {
	var m pb.EntryIndex
	err := kr.Get(ctx, buckets[indexByLeafHash][lt], lh, &m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Start pair

func writeObjectSize(ctx context.Context, kr KeyWriter, size int64) error {
	return kr.Set(ctx, metadata, objSizeKey, &pb.ObjectSize{Size: size})
}

func readObjectSize(ctx context.Context, kr KeyReader) (int64, error) {
	var lth pb.ObjectSize
	err := kr.Get(ctx, metadata, objSizeKey, &lth)
	switch err {
	case nil:
		return lth.Size, nil
	case util.ErrNoSuchKey:
		return 0, nil
	default:
		return 0, err
	}
}

func lookupLogTreeHead(ctx context.Context, kr KeyReader, lt pb.LogType) (*pb.LogTreeHashResponse, error) {
	objectSize, err := readObjectSize(ctx, kr)
	if err != nil {
		return nil, err
	}
	if objectSize == 0 {
		return &pb.LogTreeHashResponse{}, nil // zero-ed out
	}

	lth, err := lookupLogRootHashBySize(ctx, kr, lt, objectSize)
	if err != nil {
		return nil, err
	}

	return &pb.LogTreeHashResponse{
		RootHash: lth.Mth,
		TreeSize: objectSize,
	}, nil
}

// Start pair

func writeMapHash(ctx context.Context, kr KeyWriter, number int64, path util.BPath, data *pb.MapNode) error {
	return kr.Set(ctx, mapNodeBucket, append(toIntBinary(uint64(number)), path...), data)
}

func lookupMapHash(ctx context.Context, kr KeyReader, number int64, path util.BPath) (*pb.MapNode, error) {
	// Special case 0
	if number == 0 && path.Length() == 0 {
		return &pb.MapNode{}, nil
	}
	var m pb.MapNode
	err := kr.Get(ctx, mapNodeBucket, append(toIntBinary(uint64(number)), path...), &m)
	if err != nil {
		return nil, err
	}

	return &m, nil
}

// End pairs

func lookupLogEntryHashes(ctx context.Context, kr KeyReader, lt pb.LogType, first, last int64) ([][]byte, error) {
	rv := make([][]byte, last-first)
	for i := first; i < last; i++ { // if we add a range / scan operation to KeyReader, this could be quicker
		x, err := lookupLeafNodeByIndex(ctx, kr, lt, i)
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

func logBucket(log *pb.LogRef) ([]byte, error) {
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

func mapBucket(vmap *pb.MapRef) ([]byte, error) {
	return objecthash.ObjectHash(map[string]interface{}{
		"account": vmap.Account.Id,
		"name":    vmap.Name,
		"type":    "map",
	})
}
