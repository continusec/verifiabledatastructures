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
	"bytes"
	"context"

	"github.com/continusec/verifiabledatastructures/pb"
)

var (
	nullLeafHash = LeafMerkleTreeHash([]byte{})
)

// prevLeafHash must never be nil, it will often be nullLeafHash though
// Never returns nil (except on err), always returns nullLeafHash instead
func mutationLeafHash(mut *pb.MapMutation, prevLeafHash []byte) ([]byte, error) {
	switch mut.Action {
	case "set":
		return LeafMerkleTreeHash(mut.Value.LeafInput), nil
	case "delete":
		return nullLeafHash, nil
	case "update":
		if bytes.Equal(prevLeafHash, mut.PreviousLeafHash) {
			return LeafMerkleTreeHash(mut.Value.LeafInput), nil
		}
		return prevLeafHash, nil
	default:
		return nil, ErrInvalidRequest
	}
}

// returns root followed by list of map nodes, not including head which is returned separately, as far as we can descend and match
func descendToFork(ctx context.Context, db KeyReader, path BPath, root *pb.MapNode) (*pb.MapNode, []*pb.MapNode, error) {
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
			head, err = lookupMapHash(ctx, db, head.RightNumber, path.Slice(0, depth+1))
		} else { // left
			if head.LeftNumber == 0 {
				return head, rv, nil
			}
			rv = append(rv, head)
			head, err = lookupMapHash(ctx, db, head.LeftNumber, path.Slice(0, depth+1))
		}
		if err != nil {
			return nil, nil, err
		}
		depth++
	}
}

func writeAncestors(ctx context.Context, db KeyWriter, last *pb.MapNode, ancestors []*pb.MapNode, keyPath BPath, mutationIndex int64) ([]byte, error) {
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
		err := writeMapHash(ctx, db, mutationIndex+1, keyPath.Slice(0, uint(i)), last)
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

func isEmptyNode(mn *pb.MapNode) bool {
	return ((len(mn.LeafHash) == 0) || bytes.Equal(mn.LeafHash, nullLeafHash)) && mn.LeftNumber == 0 && mn.RightNumber == 0
}

func setMapValue(ctx context.Context, db KeyWriter, vmap *pb.MapRef, mutationIndex int64, mut *pb.MapMutation) ([]byte, error) {
	keyPath := BPathFromKey(mut.Key)

	// Get the root node for tree size, will never be nil
	root, err := lookupMapHash(ctx, db, mutationIndex, BPathEmpty)
	if err != nil {
		return nil, err
	}

	// First, set head to as far down as we can go
	head, ancestors, err := descendToFork(ctx, db, keyPath, root)
	if err != nil {
		return nil, err
	}

	// Get previous value to determine if we're a no-op or not
	var prevLeafHash []byte
	isMatch := bytes.Equal(head.Path, keyPath)
	if isMatch {
		prevLeafHash = head.LeafHash
	} else {
		prevLeafHash = nullLeafHash
	}
	nextLeafHash, err := mutationLeafHash(mut, prevLeafHash)
	if err != nil {
		return nil, err
	}

	// Can we short-circuit since nothing changed?
	if bytes.Equal(prevLeafHash, nextLeafHash) {
		// Then we just need to re-write root with new sequence numbers
		err = writeMapHash(ctx, db, mutationIndex+1, nil, root)
		if err != nil {
			return nil, err
		}
		return calcNodeHash(root, 0)
	}

	// Time to start writing our data
	if !bytes.Equal(nextLeafHash, nullLeafHash) {
		err = writeDataByLeafHash(ctx, db, pb.LogType_STRUCT_TYPE_MUTATION_LOG, nextLeafHash, mut.Value)
		if err != nil {
			return nil, err
		}
	}

	// OK, instead, is the leaf us exactly? If so, easy we just rewrite it.
	if isMatch || isEmptyNode(head) {
		last := &pb.MapNode{
			LeafHash: nextLeafHash,
			Path:     keyPath,
		}
		err = writeMapHash(ctx, db, mutationIndex+1, keyPath.Slice(0, uint(len(ancestors))), last)
		if err != nil {
			return nil, err
		}
		return writeAncestors(ctx, db, last, ancestors, keyPath, mutationIndex)
	}

	if len(head.LeafHash) == 0 { // node
		ancestors = append(ancestors, head) // slap another shrimp on the barbie, one of the above sides will get overwitten when we write out ancestors
	} else { // leaf
		// Add stub nodes for common ancestors
		for keyPath.At(uint(len(ancestors))) == BPath(head.Path).At(uint(len(ancestors))) {
			ancestors = append(ancestors, &pb.MapNode{}) // stub it in, we'll fill it later
		}

		// Now we create a new parent with two children, us and the previous node.
		// Was the previous node a leaf? (if not, we can skip the sibling bit)
		// Start with writing the sibling
		theirHash, err := calcNodeHash(head, uint(len(ancestors)+1))
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
		// May as well write it out now
		err = writeMapHash(ctx, db, mutationIndex+1, BPathJoin(keyPath.Slice(0, uint(len(ancestors))), appendPath), head)
		if err != nil {
			return nil, err
		}

		// Now put the parent on the pile
		ancestors = append(ancestors, par)
	}

	// And write us and them out:
	last := &pb.MapNode{
		Path:     keyPath,
		LeafHash: nextLeafHash,
	}
	err = writeMapHash(ctx, db, mutationIndex+1, keyPath.Slice(0, uint(len(ancestors))), last)
	if err != nil {
		return nil, err
	}
	return writeAncestors(ctx, db, last, ancestors, keyPath, mutationIndex)
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
