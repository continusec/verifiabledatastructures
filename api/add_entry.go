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

func (s *LocalService) writeOutLogTreeNodes(db KeyWriter, log *pb.LogRef, entryIndex int64, mtl []byte, stack [][]byte) ([]byte, error) {
	stack = append(stack, mtl)
	for zz, width := entryIndex, int64(2); (zz & 1) == 1; zz, width = zz>>1, width<<1 {
		parN := client.NodeMerkleTreeHash(stack[len(stack)-2], stack[len(stack)-1])
		stack = append(stack[:len(stack)-2], parN)
		err := s.writeTreeNodeByRange(db, log.LogType, entryIndex+1-width, entryIndex+1, &pb.TreeNode{Mth: parN})
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
func (s *LocalService) addEntryToLog(db KeyWriter, log *pb.LogRef, data *pb.LeafData) (*pb.LogTreeHashResponse, error) {
	// First, calc our hash
	mtl := client.LeafMerkleTreeHash(data.LeafInput)

	// Now, see if we already have it stored
	_, err := s.lookupIndexByLeafHash(db, log.LogType, mtl)
	switch err {
	case nil:
		// we already have it
		return nil, nil
	case ErrNoSuchKey:
		// good, continue
	default:
		return nil, err
	}

	ltr, err := s.lookupLogTreeHead(db, log.LogType)
	if err != nil {
		return nil, err
	}

	// First write the data
	err = s.writeDataByLeafHash(db, log.LogType, mtl, data)
	if err != nil {
		return nil, err
	}

	// Then write us at the index
	err = s.writeLeafNodeByIndex(db, log.LogType, ltr.TreeSize, &pb.LeafNode{Mth: mtl})
	if err != nil {
		return nil, err
	}

	// And our index by leaf hash
	err = s.writeIndexByLeafHash(db, log.LogType, mtl, &pb.EntryIndex{Index: ltr.TreeSize})
	if err != nil {
		return nil, err
	}

	// Write out needed hashes
	stack, err := s.fetchSubTreeHashes(db, log.LogType, createNeededStack(ltr.TreeSize), true)
	if err != nil {
		return nil, err
	}
	rootHash, err := s.writeOutLogTreeNodes(db, log, ltr.TreeSize, mtl, stack)
	if err != nil {
		return nil, err
	}

	// Write log root hash
	err = s.writeLogRootHashBySize(db, log.LogType, ltr.TreeSize+1, &pb.LogTreeHash{Mth: rootHash})
	if err != nil {
		return nil, err
	}

	// Update head
	rv := &pb.LogTreeHashResponse{
		RootHash: rootHash,
		TreeSize: ltr.TreeSize + 1,
	}
	err = s.writeLogTreeHead(db, log.LogType, rv)
	if err != nil {
		return nil, err
	}

	// Done!
	return rv, nil
}

func (s *LocalService) setMapValue(db KeyWriter, vmap *pb.MapRef, treeSize int64, mut *client.JSONMapMutationEntry) ([]byte, error) {
	return nil, ErrNotImplemented
}

func mapForMutationLog(m *pb.LogRef) *pb.MapRef {
	return &pb.MapRef{
		Account: m.Account,
		Name:    m.Name,
	}
}

func treeHeadLogForMutationLog(m *pb.LogRef) *pb.LogRef {
	return &pb.LogRef{
		Account: m.Account,
		Name:    m.Name,
		LogType: pb.LogType_STRUCT_TYPE_TREEHEAD_LOG,
	}
}

func (s *LocalService) applyLogAddEntry(db KeyWriter, req *pb.LogAddEntryRequest) error {
	// Step 1 - add entry to log as request
	mutLogHead, err := s.addEntryToLog(db, req.Log, req.Data)
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
		var mut client.JSONMapMutationEntry
		err = json.Unmarshal(req.Data.ExtraData, &mut)
		if err != nil {
			return err
		}
		mrh, err := s.setMapValue(db, mapForMutationLog(req.Log), mutLogHead.TreeSize, &mut)
		if err != nil {
			return err
		}

		// Step 3 - add entries to treehead log if neeed
		thld, err := jsonObjectHash(&client.JSONMapTreeHeadResponse{
			MapHash: mrh,
			LogTreeHead: &client.JSONLogTreeHeadResponse{
				Hash:     mutLogHead.RootHash,
				TreeSize: mutLogHead.TreeSize,
			},
		})
		if err != nil {
			return err
		}
		_, err = s.addEntryToLog(db, treeHeadLogForMutationLog(req.Log), thld)
		if err != nil {
			return err
		}
	}

	return nil
}
