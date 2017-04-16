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

	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/pb"
)

func writeOutLogTreeNodes(db KeyWriter, log *pb.LogRef, entryIndex int64, mtl []byte, stack [][]byte) ([]byte, error) {
	stack = append(stack, mtl)
	for zz, width := entryIndex, int64(2); (zz & 1) == 1; zz, width = zz>>1, width<<1 {
		parN := client.NodeMerkleTreeHash(stack[len(stack)-2], stack[len(stack)-1])
		stack = append(stack[:len(stack)-2], parN)
		err := writeTreeNodeByRange(db, log.LogType, entryIndex+1-width, entryIndex+1, &pb.TreeNode{Mth: parN})
		if err != nil {
			return nil, err
		}
	}
	// Collapse stack to get tree head
	headHash := stack[len(stack)-1]
	for z := len(stack) - 2; z >= 0; z-- {
		headHash = client.NodeMerkleTreeHash(stack[z], headHash)
	}
	return headHash, nil
}

// return nil, nil if already exists
func addEntryToLog(db KeyWriter, log *pb.LogRef, data *pb.LeafData) (*pb.LogTreeHashResponse, error) {
	// First, calc our hash
	mtl := client.LeafMerkleTreeHash(data.LeafInput)

	// Now, see if we already have it stored
	_, err := lookupIndexByLeafHash(db, log.LogType, mtl)
	switch err {
	case nil:
		// we already have it
		return nil, nil
	case ErrNoSuchKey:
		// good, continue
	default:
		return nil, err
	}

	ltr, err := lookupLogTreeHead(db, log.LogType)
	if err != nil {
		return nil, err
	}

	// First write the data
	err = writeDataByLeafHash(db, log.LogType, mtl, data)
	if err != nil {
		return nil, err
	}

	// Then write us at the index
	err = writeLeafNodeByIndex(db, log.LogType, ltr.TreeSize, &pb.LeafNode{Mth: mtl})
	if err != nil {
		return nil, err
	}

	// And our index by leaf hash
	err = writeIndexByLeafHash(db, log.LogType, mtl, &pb.EntryIndex{Index: ltr.TreeSize})
	if err != nil {
		return nil, err
	}

	// Write out needed hashes
	stack, err := fetchSubTreeHashes(db, log.LogType, createNeededStack(ltr.TreeSize), true)
	if err != nil {
		return nil, err
	}
	rootHash, err := writeOutLogTreeNodes(db, log, ltr.TreeSize, mtl, stack)
	if err != nil {
		return nil, err
	}

	// Write log root hash
	err = writeLogRootHashBySize(db, log.LogType, ltr.TreeSize+1, &pb.LogTreeHash{Mth: rootHash})
	if err != nil {
		return nil, err
	}

	// Update head
	rv := &pb.LogTreeHashResponse{
		RootHash: rootHash,
		TreeSize: ltr.TreeSize + 1,
	}
	err = writeLogTreeHead(db, log.LogType, rv)
	if err != nil {
		return nil, err
	}

	// Done!
	return rv, nil
}

func applyLogAddEntry(db KeyWriter, req *pb.LogAddEntryRequest) error {
	// Step 1 - add entry to log as request
	mutLogHead, err := addEntryToLog(db, req.Log, req.Value)
	if err != nil {
		return err
	}

	// Was it already in the log? If so, we were called in error so quit early
	if mutLogHead == nil {
		return nil
	}

	// Special case mutation log for maps
	if req.Log.LogType == pb.LogType_STRUCT_TYPE_MUTATION_LOG {
		// Step 2 - add entries to map if needed
		var mut pb.MapMutation
		err = json.Unmarshal(req.Value.ExtraData, &mut)
		if err != nil {
			return err
		}
		mrh, err := setMapValue(db, mapForMutationLog(req.Log), mutLogHead.TreeSize-1, &mut)
		if err != nil {
			return err
		}

		// Step 3 - add entries to treehead log if neeed
		thld, err := jsonObjectHash(&pb.MapTreeHashResponse{
			RootHash:    mrh,
			MutationLog: mutLogHead,
		})
		if err != nil {
			return err
		}
		_, err = addEntryToLog(db, treeHeadLogForMutationLog(req.Log), thld)
		if err != nil {
			return err
		}
	}

	return nil
}
