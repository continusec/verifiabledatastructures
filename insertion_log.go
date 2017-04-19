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
)

func writeOutLogTreeNodes(db KeyWriter, log *LogRef, entryIndex int64, mtl []byte, stack [][]byte) ([]byte, error) {
	stack = append(stack, mtl)
	for zz, width := entryIndex, int64(2); (zz & 1) == 1; zz, width = zz>>1, width<<1 {
		parN := NodeMerkleTreeHash(stack[len(stack)-2], stack[len(stack)-1])
		stack = append(stack[:len(stack)-2], parN)
		err := writeTreeNodeByRange(db, log.LogType, entryIndex+1-width, entryIndex+1, &TreeNode{Mth: parN})
		if err != nil {
			return nil, err
		}
	}
	// Collapse stack to get tree head
	headHash := stack[len(stack)-1]
	for z := len(stack) - 2; z >= 0; z-- {
		headHash = NodeMerkleTreeHash(stack[z], headHash)
	}
	return headHash, nil
}

// Must be idempotent, ie call it many times with same result.
// return nil, nil if already exists
func addEntryToLog(db KeyWriter, sizeBefore int64, log *LogRef, data *LeafData) (*LogTreeHashResponse, error) {
	// First, calc our hash
	mtl := LeafMerkleTreeHash(data.LeafInput)

	// Now, see if we already have it stored
	ei, err := lookupIndexByLeafHash(db, log.LogType, mtl)
	switch err {
	case nil:
		if ei.Index < sizeBefore {
			// we already have it
			return nil, nil
		}
		// else, we don't technically have it yet, so continue
	case ErrNoSuchKey:
		// good, continue
	default:
		return nil, err
	}

	// First write the data
	err = writeDataByLeafHash(db, log.LogType, mtl, data)
	if err != nil {
		return nil, err
	}

	// Then write us at the index
	err = writeLeafNodeByIndex(db, log.LogType, sizeBefore, &LeafNode{Mth: mtl})
	if err != nil {
		return nil, err
	}

	// And our index by leaf hash
	err = writeIndexByLeafHash(db, log.LogType, mtl, &EntryIndex{Index: sizeBefore})
	if err != nil {
		return nil, err
	}

	// Write out needed hashes
	stack, err := fetchSubTreeHashes(db, log.LogType, createNeededStack(sizeBefore), true)
	if err != nil {
		return nil, err
	}
	rootHash, err := writeOutLogTreeNodes(db, log, sizeBefore, mtl, stack)
	if err != nil {
		return nil, err
	}

	// Write log root hash
	err = writeLogRootHashBySize(db, log.LogType, sizeBefore+1, &LogTreeHash{Mth: rootHash})
	if err != nil {
		return nil, err
	}
	// Done!
	return &LogTreeHashResponse{
		RootHash: rootHash,
		TreeSize: sizeBefore + 1,
	}, nil
}

func applyLogAddEntry(db KeyWriter, sizeBefore int64, req *LogAddEntryRequest) (int64, error) {
	// Step 1 - add entry to log as request
	mutLogHead, err := addEntryToLog(db, sizeBefore, req.Log, req.Value)
	if err != nil {
		return 0, err
	}

	// Was it already in the log? If so, we were called in error so quit early
	if mutLogHead == nil {
		return sizeBefore, nil
	}

	// Special case mutation log for maps
	if req.Log.LogType == LogType_STRUCT_TYPE_MUTATION_LOG {
		// Step 2 - add entries to map if needed
		var mut MapMutation
		err = json.Unmarshal(req.Value.ExtraData, &mut)
		if err != nil {
			return 0, err
		}
		mrh, err := setMapValue(db, mapForMutationLog(req.Log), sizeBefore, &mut)
		if err != nil {
			return 0, err
		}

		// Step 3 - add entries to treehead log if neeed
		thld, err := CreateJSONLeafDataFromProto(&MapTreeHashResponse{
			RootHash:    mrh,
			MutationLog: mutLogHead,
		})
		if err != nil {
			return 0, err
		}
		_, err = addEntryToLog(db, sizeBefore, treeHeadLogForMutationLog(req.Log), thld)
		if err != nil {
			return 0, err
		}
	}

	return sizeBefore + 1, nil
}
