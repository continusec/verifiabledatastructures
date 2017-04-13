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
	case "delete":
		return nullLeafHash, nil
	case "set":
		return client.LeafMerkleTreeHash(mut.ValueLeafInput), nil
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
func (s *LocalService) descendToFork(db KeyReader, path BPath, root *pb.MapNode) (*pb.MapNode, []*pb.MapNode, error) {
	rv := make([]*pb.MapNode, 0)
	head := root
	depth := uint(0)
	var err error
	for {
		if path.At(depth) { // right
			if head.RightNumber == 0 {
				return head, rv, nil
			}
			head, err = s.lookupMapHash(db, head.RightNumber, path.Slice(0, depth+1))

		} else { //left
			if head.LeftNumber == 0 {
				return head, rv, nil
			}
			head, err = s.lookupMapHash(db, head.LeftNumber, path.Slice(0, depth+1))
		}
		if err != nil {
			return nil, nil, err
		}
		rv = append(rv, head)
		depth++
	}
}

func mapNodeIsLeaf(n *pb.MapNode) bool {
	return n.LeftNumber == 0 && n.RightNumber == 0
}

func mapNodeRemainingMatches(n *pb.MapNode, kp BPath) bool {
	l := kp.Length()
	return bytes.Equal(kp.Slice(l-BPath(n.RemainingPath).Length(), l), n.RemainingPath)
}

func (s *LocalService) writeAncestors(db KeyWriter, last *vMapNode, ancestors []*pb.MapNode, keyPath BPath, mutationIndex int64) ([]byte, error) {
	// Write out ancestor chain
	curHash := last.calcNodeHash(uint(len(ancestors)))
	for i := len(ancestors) - 1; i >= 0; i-- {
		if keyPath.At(uint(i)) {
			last = (*vMapNode)(&pb.MapNode{
				LeftNumber:  ancestors[i].LeftNumber,
				LeftHash:    ancestors[i].LeftHash,
				RightNumber: mutationIndex + 1,
				RightHash:   curHash,
			})
		} else {
			last = (*vMapNode)(&pb.MapNode{
				LeftNumber:  mutationIndex + 1,
				LeftHash:    curHash,
				RightNumber: ancestors[i].RightNumber,
				RightHash:   ancestors[i].RightHash,
			})
		}
		err := s.writeMapHash(db, mutationIndex+1, keyPath.Slice(0, uint(i)), (*pb.MapNode)(last))
		if err != nil {
			return nil, err
		}
		curHash = last.calcNodeHash(uint(i))
	}

	return curHash, nil

}

func (s *LocalService) setMapValue(db KeyWriter, vmap *pb.MapRef, mutationIndex int64, mut *client.JSONMapMutationEntry) ([]byte, error) {
	// Get the root node for tree size, will never be nil
	root, err := s.lookupMapHash(db, mutationIndex, nil)
	if err != nil {
		return nil, err
	}

	keyPath := BPathFromKey(mut.Key)

	// First, set head to as far down as we can go
	head, ancestors, err := s.descendToFork(db, keyPath, root)
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

	// Can we short-circuit since nothing changed?
	if bytes.Equal(prevLeafHash, nextLeafHash) {
		// Then we just need to re-write root with new sequence numbers
		err = s.writeMapHash(db, mutationIndex+1, nil, root)
		if err != nil {
			return nil, err
		}
		return (*vMapNode)(root).calcNodeHash(0), nil
	}

	// OK, instead, is the leaf us exactly? If so, easy we just rewrite it.
	if isMatch {
		last := (*vMapNode)(&pb.MapNode{
			LeafHash:      nextLeafHash,
			RemainingPath: head.RemainingPath,
		})
		last.setLeftRightForData()
		err = s.writeMapHash(db, mutationIndex+1, keyPath.Slice(0, uint(len(ancestors))), (*pb.MapNode)(last))
		if err != nil {
			return nil, err
		}
		return s.writeAncestors(db, last, ancestors, keyPath, mutationIndex)
	}

	/*
		// Since we are a leaf, start slapping some extra parents in
		newParsNeeded := BPathCommonPrefixLength(keyPath.Slice(uint(len(ancestors)+1), keyPath.Length()), head.RemainingPath)
		for i := uint(0); i < newParsNeeded; i++ {
			all = append(all, &pb.MapNode{})
		}
		head = &pb.MapNode{
			LeafHash:      head.LeafHash,
			RemainingPath: BPath(head.RemainingPath).Slice(newParsNeeded, BPath(head.RemainingPath).Length()),
		}

		// If we haven't found our leaf
		// Now, create as many single parents as needed until we diverge
		for next := head; next.Leaf && keyPath.At(next.Depth-1) == next.KeyPath.At(next.Depth-1); {
			head = next
			child := &mapAuditNode{
				Depth:    head.Depth + 1,
				Leaf:     true,
				KeyPath:  head.KeyPath,
				LeafHash: head.LeafHash,
			}
			head.Leaf, head.LeafHash, head.KeyPath = false, nil, nil
			if child.KeyPath.At(head.Depth) {
				head.Left, head.Right = nil, child
			} else {
				head.Left, head.Right = child, nil
			}
			head.Hash = nil
			next = child
		}
		child := &mapAuditNode{
			Depth:    head.Depth + 1,
			Leaf:     true,
			KeyPath:  keyPath,
			LeafHash: nullLeafHash,
		}
		if child.KeyPath.At(head.Depth) {
			head.Right = child
		} else {
			head.Left = child
		}
		head.Hash = nil
		head = child

		head.LeafHash = nextLeafHash
		head.Hash = nil

		return root.CalcHash(), nil
	*/
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
