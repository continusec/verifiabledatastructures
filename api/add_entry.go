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

var (
	nullLeafHash = client.LeafMerkleTreeHash([]byte{})
)

// prevLeafHash is never nil, it will often be nullLeafHash though
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

type mapNodeWriter func(mn *pb.MapNode) error
type mapNodeReader func(int64, BPath) (*pb.MapNode, error)

// Actually write the leaf. This may return nil, meaning that it was not necessary to write a new leaf, unless alwaysWrite is set.
func handleWritingLeaf(writer mapNodeWriter, leafPath BPath, nextSequence int64, depth uint, mut *client.JSONMapMutationEntry, prev *pb.MapNode, alwaysWrite bool) (*pb.MapNode, error) {
	var prevVal []byte
	if prev != nil {
		prevVal = prev.DataHash
	}
	if len(prevVal) == 0 {
		prevVal = nullLeafHash
	}
	ourVal, err := mutationLeafHash(mut, prevVal)
	if err != nil {
		return nil, err
	}

	if !alwaysWrite {
		if bytes.Equal(prevVal, ourVal) {
			return nil, nil // mean do nothing
		}
	}

	leaf := &pb.MapNode{
		Number:        nextSequence,
		Path:          leafPath.Slice(0, depth),
		RemainingPath: leafPath.Slice(depth, 256),
		DataHash:      ourVal,
	}
	err = writer(leaf)
	if err != nil {
		return nil, err
	}
	return leaf, nil
}

/*func (s *LocalService) setMapValue(db KeyWriter, vmap *pb.MapRef, treeSize int64, mut *client.JSONMapMutationEntry) (*pb.MapNode, error) {
	writer := func(mn *pb.MapNode) error {
		return s.writeMapHash(db, mn.Number, mn.Path, mn)
	}
	reader := func(ts int64, p BPath) (*pb.MapNode, error) {
		return s.lookupMapHash(db, ts, p)
	}

	leafPath := BPathFromKey(mut.Key)
	if treeSize == 0 {
		return handleWritingLeaf(writer, leafPath, treeSize, 0, mut, nil, true)
	}

	head, err := s.lookupMapHash(db, treeSize, nil)
	if err != nil {
		return nil, err
	}

	if (head.LeftNumber == 0) && (head.RightNumber == 0) && (len(head.DataHash) == 0) { // we are root, special case
		return handleWritingLeaf(writer, leafPath, treeSize, 0, mut, nil, true)
	}

	return descendAndHandle(writer, reader, head, treeSize, treeSize, 0, nil, leafPath, mut, treeSize)
}*/

func mapNodeIsLeaf(mn *pb.MapNode) bool {
	return mn.LeftNumber == 0 && mn.RightNumber == 0
}

// MapAuditNode is an internal structure used for auditing maps
// It holds the current state of a map and is not go-routine safe.
type mapAuditNode struct {
	// Calculated hash for this node, can be nil to indicate invalid
	Hash []byte

	// Our depth
	Depth uint

	// Is this node a leaf? If so, left/right are ignored and RemPath/LeafHash must be set
	Leaf bool

	// Ignored if unless leaf is set. Remaining Path
	KeyPath BPath

	// Ignored if unless leaf is set. Actual value (differs from Hash since Hash takes into account RemPath)
	LeafHash []byte

	// The Left and Right child nodes. May be nil.
	Left, Right *mapAuditNode

	// Original
	Original *pb.MapNode
	Reader   KeyGetter
	Service  *LocalService
}

/*type nodeWrapper struct {
	Original *pb.MapNode

	left, right *nodeWrapper
}

func (n *nodeWrapper) Left() (*nodeWrapper, error) {

}*/

// Return hash for this node, calculating if necessary
func (node *mapAuditNode) CalcHash() []byte {
	if node.Hash == nil {
		if node.Leaf {
			node.Hash = node.LeafHash
			for i := uint(256); i > node.Depth; i-- {
				if node.KeyPath.At(i - 1) {
					node.Hash = client.NodeMerkleTreeHash(defaultLeafValues[i], node.Hash)
				} else {
					node.Hash = client.NodeMerkleTreeHash(node.Hash, defaultLeafValues[i])
				}
			}
		} else {
			var left, right []byte
			if node.Left == nil {
				left = defaultLeafValues[node.Depth+1]
			} else {
				left = node.Left.CalcHash()
			}
			if node.Right == nil {
				right = defaultLeafValues[node.Depth+1]
			} else {
				right = node.Right.CalcHash()
			}
			node.Hash = client.NodeMerkleTreeHash(left, right)
		}
	}
	return node.Hash
}

func (s *LocalService) mapAuditNodeWrapped(db KeyGetter, orig *pb.MapNode) *mapAuditNode {
	return &mapAuditNode{
		Depth:    BPath(orig.Path).Length(),
		KeyPath:  BPathJoin(orig.Path, orig.RemainingPath),
		Leaf:     (orig.LeftNumber == 0) && (orig.RightNumber == 0),
		LeafHash: orig.DataHash,
		Original: orig,
		Reader:   db,
		Service:  s,
	}
}

func (m *mapAuditNode) FetchLeft() (*mapAuditNode, error) {
	if m.Original.LeftNumber == 0 {
		return nil, nil
	}
	mn, err := m.Service.lookupMapHash(m.Reader, m.Original.LeftNumber, BPathJoin(m.Original.Path, BPathFalse))
	if err != nil {
		return nil, err
	}
	return m.Service.mapAuditNodeWrapped(m.Reader, mn), nil
}

func (m *mapAuditNode) FetchRight() (*mapAuditNode, error) {
	if m.Original.LeftNumber == 0 {
		return nil, nil
	}
	mn, err := m.Service.lookupMapHash(m.Reader, m.Original.RightNumber, BPathJoin(m.Original.Path, BPathTrue))
	if err != nil {
		return nil, err
	}
	return m.Service.mapAuditNodeWrapped(m.Reader, mn), nil
}

// Given a root node, update it with a given map mutation, returning the new
// root hash.
func (s *LocalService) addMutationToTree(db KeyWriter, vmap *pb.MapRef, mutationIndex int64, mut *client.JSONMapMutationEntry) ([]byte, error) {
	keyPath := BPathFromKey(mut.Key)
	mn, err := s.lookupMapHash(db, mutationIndex, nil)
	if err != nil {
		return nil, err
	}
	root := s.mapAuditNodeWrapped(db, mn)
	head := root

	// First, set head to as far down as we can go
	for next := head; next != nil; {
		head.Hash = nil
		head = next
		if keyPath.At(head.Depth) {
			next, err = head.FetchRight()
		} else {
			next, err = head.FetchLeft()
		}
		if err != nil {
			return nil, err
		}
	}

	// If we haven't found our leaf
	if !(head.Leaf && bytes.Equal(keyPath, head.KeyPath)) {
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
			LeafHash: defaultLeafValues[256],
		}
		if child.KeyPath.At(head.Depth) {
			head.Right = child
		} else {
			head.Left = child
		}
		head.Hash = nil
		head = child
	}

	switch mut.Action {
	case "set":
		head.LeafHash = client.LeafMerkleTreeHash(mut.ValueLeafInput)
	case "delete":
		head.LeafHash = defaultLeafValues[256]
	case "update":
		if bytes.Equal(head.LeafHash, mut.PreviousLeafHash) {
			head.LeafHash = client.LeafMerkleTreeHash(mut.ValueLeafInput)
		}
	default:
		return nil, ErrInvalidRequest
	}
	head.Hash = nil

	return root.CalcHash(), nil
}

func (s *LocalService) setMapValue(db KeyWriter, vmap *pb.MapRef, mutationIndex int64, mut *client.JSONMapMutationEntry) (*pb.MapNode, error) {
	// Get the root node for tree size, will never be nil
	/*head, err := s.lookupMapHash(db, mutationIndex, nil)
	if err != nil {
		return nil, err
	}

	keyPath := BPathFromKey(mut.Key)*/

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
			MapHash: (*vMapNode)(mrh).calcNodeHash(),
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
