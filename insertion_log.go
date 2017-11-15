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
	"encoding/json"

	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/util"
)

func writeOutLogTreeNodes(ctx context.Context, db KeyWriter, log *pb.LogRef, entryIndex int64, mtl []byte, stack [][]byte) ([]byte, error) {
	stack = append(stack, mtl)
	for zz, width := entryIndex, int64(2); (zz & 1) == 1; zz, width = zz>>1, width<<1 {
		parN := util.NodeMerkleTreeHash(stack[len(stack)-2], stack[len(stack)-1])
		stack = append(stack[:len(stack)-2], parN)
		err := writeTreeNodeByRange(ctx, db, log.LogType, entryIndex+1-width, entryIndex+1, &pb.TreeNode{Mth: parN})
		if err != nil {
			return nil, err
		}
	}
	// Collapse stack to get tree head
	headHash := stack[len(stack)-1]
	for z := len(stack) - 2; z >= 0; z-- {
		headHash = util.NodeMerkleTreeHash(stack[z], headHash)
	}
	return headHash, nil
}

// Must be idempotent, ie call it many times with same result.
// return nil, nil if already exists
func addEntryToLog(ctx context.Context, db KeyWriter, sizeBefore int64, log *pb.LogRef, data *pb.LeafData) (*pb.LogTreeHashResponse, error) {
	// First, calc our hash
	mtl := util.LeafMerkleTreeHash(data.LeafInput)

	// Now, see if we already have it stored
	ei, err := lookupIndexByLeafHash(ctx, db, log.LogType, mtl)
	switch err {
	case nil:
		if ei.Index < sizeBefore {
			// we already have it
			return nil, nil
		}
		// else, we don't technically have it yet, so continue
	case util.ErrNoSuchKey:
		// good, continue
	default:
		return nil, err
	}

	// First write the data
	err = writeDataByLeafHash(ctx, db, log.LogType, mtl, data)
	if err != nil {
		return nil, err
	}

	// Then write us at the index
	err = writeLeafNodeByIndex(ctx, db, log.LogType, sizeBefore, &pb.LeafNode{Mth: mtl})
	if err != nil {
		return nil, err
	}

	// And our index by leaf hash
	err = writeIndexByLeafHash(ctx, db, log.LogType, mtl, &pb.EntryIndex{Index: sizeBefore})
	if err != nil {
		return nil, err
	}

	// Write out needed hashes
	stack, err := fetchSubTreeHashes(ctx, db, log.LogType, util.CreateNeededStack(sizeBefore), true)
	if err != nil {
		return nil, err
	}
	rootHash, err := writeOutLogTreeNodes(ctx, db, log, sizeBefore, mtl, stack)
	if err != nil {
		return nil, err
	}

	// Write log root hash
	err = writeLogRootHashBySize(ctx, db, log.LogType, sizeBefore+1, &pb.LogTreeHash{Mth: rootHash})
	if err != nil {
		return nil, err
	}
	// Done!
	return &pb.LogTreeHashResponse{
		RootHash: rootHash,
		TreeSize: sizeBefore + 1,
	}, nil
}

func applyLogAddEntry(ctx context.Context, db KeyWriter, sizeBefore int64, req *pb.LogAddEntryRequest) (int64, error) {
	// Step 1 - add entry to log as request
	mutLogHead, err := addEntryToLog(ctx, db, sizeBefore, req.Log, req.Value)
	if err != nil {
		return 0, err
	}

	// Was it already in the log? If so, we were called in error so quit early
	if mutLogHead == nil {
		return sizeBefore, nil
	}

	// Special case mutation log for maps
	if req.Log.LogType == pb.LogType_STRUCT_TYPE_MUTATION_LOG {
		// Step 2 - add entries to map if needed
		var mut pb.MapMutation
		err = json.Unmarshal(req.Value.ExtraData, &mut)
		if err != nil {
			return 0, err
		}
		mrh, err := setMapValue(ctx, db, mapForMutationLog(req.Log), sizeBefore, &mut)
		if err != nil {
			return 0, err
		}

		// Step 3 - add entries to treehead log if neeed
		thld, err := util.CreateJSONLeafDataFromProto(&pb.MapTreeHashResponse{
			RootHash:    mrh,
			MutationLog: mutLogHead,
		})
		if err != nil {
			return 0, err
		}
		_, err = addEntryToLog(ctx, db, sizeBefore, treeHeadLogForMutationLog(req.Log), thld)
		if err != nil {
			return 0, err
		}
	}

	return sizeBefore + 1, nil
}
