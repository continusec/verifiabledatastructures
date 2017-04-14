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
	"bytes"
	"log"

	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/pb"
)

var (
	nullLeafHash = client.LeafMerkleTreeHash([]byte{})
)

// prevLeafHash must never be nil, it will often be nullLeafHash though
// Never returns nil (except on err), always returns nullLeafHash instead
func mutationLeafHash(mut *client.JSONMapMutationEntry, prevLeafHash []byte) ([]byte, error) {
	switch mut.Action {
	case "set":
		return client.LeafMerkleTreeHash(mut.ValueLeafInput), nil
	case "delete":
		return nullLeafHash, nil
	case "update":
		if bytes.Equal(prevLeafHash, mut.PreviousLeafHash) {
			return client.LeafMerkleTreeHash(mut.ValueLeafInput), nil
		}
		return prevLeafHash, nil
	default:
		return nil, ErrInvalidRequest
	}
}

// returns root followed by list of map nodes, not including head which is returned separately, as far as we can descend and match
func descendToFork(db KeyReader, path BPath, root *pb.MapNode) (*pb.MapNode, []*pb.MapNode, error) {
	rv := []*pb.MapNode{}
	head := root
	depth := uint(0)
	var err error
	for {
		if path.At(depth) { // right
			if head.RightNumber == 0 {
				return head, rv, nil
			}
			rv = append(rv, head)
			head, err = lookupMapHash(db, head.RightNumber, path.Slice(0, depth+1))
		} else { // left
			if head.LeftNumber == 0 {
				return head, rv, nil
			}
			rv = append(rv, head)
			head, err = lookupMapHash(db, head.LeftNumber, path.Slice(0, depth+1))
		}
		if err != nil {
			log.Println("Error", err)
			return nil, nil, err
		}
		depth++
	}
}

func mapNodeIsLeaf(n *pb.MapNode) bool {
	return len(n.LeafHash) != 0
}

func mapNodeRemainingMatches(n *pb.MapNode, kp BPath) bool {
	l := kp.Length()
	return bytes.Equal(kp.Slice(l-BPath(n.RemainingPath).Length(), l), n.RemainingPath)
}

func writeAncestors(db KeyWriter, last *pb.MapNode, ancestors []*pb.MapNode, keyPath BPath, mutationIndex int64) ([]byte, error) {
	// Write out ancestor chain
	curHash, err := calcNodeHash(last, uint(len(ancestors)))
	if err != nil {
		return nil, err
	}

	for i := len(ancestors) - 1; i >= 0; i-- {
		if keyPath.At(uint(i)) {
			last = &pb.MapNode{
				LeftNumber:  ancestors[i].LeftNumber,
				LeftHash:    ancestors[i].LeftHash,
				RightNumber: mutationIndex + 1,
				RightHash:   curHash,
			}
		} else {
			last = &pb.MapNode{
				LeftNumber:  mutationIndex + 1,
				LeftHash:    curHash,
				RightNumber: ancestors[i].RightNumber,
				RightHash:   ancestors[i].RightHash,
			}
		}
		err := writeMapHash(db, mutationIndex+1, keyPath.Slice(0, uint(i)), last)
		if err != nil {
			return nil, err
		}
		curHash, err = calcNodeHash(last, uint(i))
		if err != nil {
			return nil, err
		}
	}
	return curHash, nil
}

func setMapValue(db KeyWriter, vmap *pb.MapRef, mutationIndex int64, mut *client.JSONMapMutationEntry) ([]byte, error) {
	keyPath := BPathFromKey(mut.Key)
	log.Println("KEY", keyPath.Str())

	// Get the root node for tree size, will never be nil
	root, err := lookupMapHash(db, mutationIndex, BPathEmpty)
	if err != nil {
		return nil, err
	}

	// First, set head to as far down as we can go
	head, ancestors, err := descendToFork(db, keyPath, root)
	if err != nil {
		return nil, err
	}

	// Get previous value to determine if we're a no-op or not
	var prevLeafHash []byte
	isMatch := mapNodeRemainingMatches(head, keyPath)
	if isMatch {
		prevLeafHash = head.LeafHash
	} else {
		prevLeafHash = nullLeafHash
	}
	nextLeafHash, err := mutationLeafHash(mut, prevLeafHash)
	if err != nil {
		return nil, err
	}
	log.Println("NEWLEAF", nextLeafHash)

	log.Println("ANCESTORS", ancestors)

	// Can we short-circuit since nothing changed?
	if bytes.Equal(prevLeafHash, nextLeafHash) {
		// Then we just need to re-write root with new sequence numbers
		err = writeMapHash(db, mutationIndex+1, nil, root)
		if err != nil {
			return nil, err
		}
		return calcNodeHash(root, 0)
	}

	log.Println("HERE")

	// Time to start writing our data
	err = writeDataByLeafHash(db, pb.LogType_STRUCT_TYPE_MUTATION_LOG, nextLeafHash, &pb.LeafData{
		LeafInput: mut.ValueLeafInput,
		ExtraData: mut.ValueExtraData,
	})
	if err != nil {
		return nil, err
	}

	// OK, instead, is the leaf us exactly? If so, easy we just rewrite it.
	if isMatch {
		last := &pb.MapNode{
			LeafHash:      nextLeafHash,
			RemainingPath: keyPath.Slice(uint(len(ancestors)), keyPath.Length()),
		}
		err = writeMapHash(db, mutationIndex+1, keyPath.Slice(0, uint(len(ancestors))), last)
		if err != nil {
			return nil, err
		}
		return writeAncestors(db, last, ancestors, keyPath, mutationIndex)
	}

	log.Println("HERE2")

	// Add stub nodes for common ancestors
	for keyPath.At(uint(len(ancestors))) == BPath(head.RemainingPath).At(0) {
		ancestors = append(ancestors, &pb.MapNode{}) // stub it in, we'll fill it later
		log.Println("adding stub")
		head = &pb.MapNode{
			LeafHash:      head.LeafHash,
			RemainingPath: BPath(head.RemainingPath).Slice(1, BPath(head.RemainingPath).Length()), // not efficient - let's get it correct first and tidy up ldate
		}
	}

	// Now we create a new parent with two children, us and the previous node.
	// Start with writing the sibling
	them := &pb.MapNode{
		LeafHash:      head.LeafHash,
		RemainingPath: BPath(head.RemainingPath).Slice(1, BPath(head.RemainingPath).Length()),
	}
	log.Println("HERE3")
	theirHash, err := calcNodeHash(them, uint(len(ancestors)+1))
	if err != nil {
		return nil, err
	}
	par := &pb.MapNode{}
	var appendPath BPath
	if keyPath.At(uint(len(ancestors))) { // us right, them left
		appendPath = BPathFalse
		par.LeftNumber = mutationIndex + 1
		par.LeftHash = theirHash
	} else {
		appendPath = BPathTrue
		par.RightNumber = mutationIndex + 1
		par.RightHash = theirHash
	}
	log.Println("HERE4")
	// May as well write it out now
	err = writeMapHash(db, mutationIndex+1, BPathJoin(keyPath.Slice(0, uint(len(ancestors))), appendPath), them)
	if err != nil {
		return nil, err
	}
	log.Println("HERE5")

	// Now put the parent on the pile
	ancestors = append(ancestors, par)

	// And write us and them out:
	last := &pb.MapNode{
		LeafHash:      nextLeafHash,
		RemainingPath: keyPath.Slice(uint(len(ancestors)), keyPath.Length()),
	}
	err = writeMapHash(db, mutationIndex+1, keyPath.Slice(0, uint(len(ancestors))), last)
	if err != nil {
		return nil, err
	}
	return writeAncestors(db, last, ancestors, keyPath, mutationIndex)
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
