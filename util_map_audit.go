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
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/util"
	"golang.org/x/net/context"
)

// MapAuditNode is an internal structure used for auditing maps
// It holds the current state of a map and is not go-routine safe.
type mapAuditNode struct {
	// Calculated hash for this node, can be nil to indicate invalid
	Hash []byte

	// Our depth
	Depth int

	// Is this node a leaf? If so, left/right are ignored and RemPath/LeafHash must be set
	Leaf bool

	// Ignored if unless leaf is set. Remaining Path
	KeyPath []bool

	// Ignored if unless leaf is set. Actual value (differs from Hash since Hash takes into account RemPath)
	LeafHash []byte

	// The Left and Right child nodes. May be nil.
	Left, Right *mapAuditNode
}

// Dump the map node and children to stdout
func (node *mapAuditNode) Dump() {
	if node.Leaf {
		fmt.Printf("%*sLeaf (%d)\n", node.Depth*4, "", node.Depth)
	} else {
		fmt.Printf("%*sParent (%d)\n", node.Depth*4, "", node.Depth)
		fmt.Printf("%*sLeft\n", node.Depth*4, "")
		if node.Left == nil {
			fmt.Printf("%*sdefault\n", (node.Depth+1)*4, "")
		} else {
			node.Left.Dump()
		}
		fmt.Printf("%*sRight\n", node.Depth*4, "")
		if node.Right == nil {
			fmt.Printf("%*sdefault\n", (node.Depth+1)*4, "")
		} else {
			node.Right.Dump()
		}
	}
}

// Return hash for this node, calculating if necessary
func (node *mapAuditNode) CalcHash() []byte {
	if node.Hash == nil {
		if node.Leaf {
			node.Hash = node.LeafHash
			for i := 256; i > node.Depth; i-- {
				if node.KeyPath[i-1] {
					node.Hash = util.NodeMerkleTreeHash(util.DefaultLeafValues[i], node.Hash)
				} else {
					node.Hash = util.NodeMerkleTreeHash(node.Hash, util.DefaultLeafValues[i])
				}
			}
		} else {
			var left, right []byte
			if node.Left == nil {
				left = util.DefaultLeafValues[node.Depth+1]
			} else {
				left = node.Left.CalcHash()
			}
			if node.Right == nil {
				right = util.DefaultLeafValues[node.Depth+1]
			} else {
				right = node.Right.CalcHash()
			}
			node.Hash = util.NodeMerkleTreeHash(left, right)
		}
	}
	return node.Hash
}

// Given a root node, update it with a given map mutation, returning the new
// root hash.
func addMutationToTree(root *mapAuditNode, mut *pb.MapMutation) ([]byte, error) {
	keyPath := util.ConstructMapKeyPath(mut.Key)
	head := root

	// First, set head to as far down as we can go
	for next := head; next != nil; {
		head.Hash = nil
		head = next
		if keyPath[head.Depth] {
			next = head.Right
		} else {
			next = head.Left
		}
	}

	// If we haven't found our leaf
	if !(head.Leaf && reflect.DeepEqual(keyPath, head.KeyPath)) {
		// Now, create as many single parents as needed until we diverge
		for next := head; next.Leaf && keyPath[next.Depth-1] == next.KeyPath[next.Depth-1]; {
			head = next
			child := &mapAuditNode{
				Depth:    head.Depth + 1,
				Leaf:     true,
				KeyPath:  head.KeyPath,
				LeafHash: head.LeafHash,
			}
			head.Leaf, head.LeafHash, head.KeyPath = false, nil, nil
			if child.KeyPath[head.Depth] {
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
			LeafHash: util.DefaultLeafValues[256],
		}
		if child.KeyPath[head.Depth] {
			head.Right = child
		} else {
			head.Left = child
		}
		head.Hash = nil
		head = child
	}

	switch mut.Action {
	case "set":
		head.LeafHash = util.LeafMerkleTreeHash(mut.Value.LeafInput)
	case "delete":
		head.LeafHash = util.DefaultLeafValues[256]
	case "update":
		if bytes.Equal(head.LeafHash, mut.PreviousLeafHash) {
			head.LeafHash = util.LeafMerkleTreeHash(mut.Value.LeafInput)
		}
	default:
		return nil, util.ErrVerificationFailed
	}
	head.Hash = nil

	return root.CalcHash(), nil
}

type auditState struct {
	// Must be set
	Map *VerifiableMap

	// Current mutation log tree head
	MutLogHead *pb.LogTreeHashResponse

	// Audit function, called for each mutation that changes the map
	MapAuditFunction MapAuditFunction

	// Called for each value on each mutation, regardless of whether it affects the map hash
	LeafDataAuditFunction LeafDataAuditFunction

	// Not set:
	Root            mapAuditNode // not a pointer so that we get good empty value
	MutLogHashStack [][]byte

	Size                 int64 // number of mutations processed, parallel arrays below
	MutationLogTreeHeads [][]byte
	MapTreeHeads         [][]byte
}

// Move the state of the audit forward to the specified size.
func (a *auditState) ProcessUntilAtLeast(ctx context.Context, size int64) error {
	// Do we need to do any work?
	if size > a.Size {
		// For now, always just fetch until head - else we'd be fetching one entry at a time
		mutLog := a.Map.MutationLog()

		// Get the lastest tree head for the mutation log
		mutLogHead, err := mutLog.VerifiedLatestTreeHead(ctx, a.MutLogHead)
		if err != nil {
			return err
		}

		// Save this off, we need to compare later
		lastRootHash := a.Root.CalcHash()

		// Perform audit of the mutation log, providing a special function to apply mutations
		// to our copy of the map
		err = mutLog.VerifyEntries(ctx, a.MutLogHead, mutLogHead, func(ctx context.Context, idx int64, entry *pb.LeafData) error {
			// First, verify that the pb.LeafData is in fact well formed objecthash
			err := util.ValidateJSONLeafDataFromMutation(entry)
			if err != nil {
				return err
			}

			// At this point, we're satisfied that mutation log entry extra data is OK

			// Decode it into standard structure
			var mutation pb.MapMutation
			err = json.Unmarshal(entry.ExtraData, &mutation)
			if err != nil {
				return err
			}

			if a.LeafDataAuditFunction != nil {
				err = a.LeafDataAuditFunction(ctx, mutation.Value)
				if err != nil {
					return err
				}
			}

			// Apply it to our copy of the map
			rh, err := addMutationToTree(&a.Root, &mutation)
			if err != nil {
				return err
			}

			// Keep our own copy of the mutation log hash stack so that we can
			// verify the mutation log heads as well.
			lh := util.LeafMerkleTreeHash(entry.LeafInput)

			// Apply to stack
			a.MutLogHashStack = append(a.MutLogHashStack, lh)
			for z := idx; (z & 1) == 1; z >>= 1 {
				a.MutLogHashStack = append(a.MutLogHashStack[:len(a.MutLogHashStack)-2], util.NodeMerkleTreeHash(a.MutLogHashStack[len(a.MutLogHashStack)-2], a.MutLogHashStack[len(a.MutLogHashStack)-1]))
			}

			// Save off current one
			headHash := a.MutLogHashStack[len(a.MutLogHashStack)-1]
			for z := len(a.MutLogHashStack) - 2; z >= 0; z-- {
				headHash = util.NodeMerkleTreeHash(a.MutLogHashStack[z], headHash)
			}

			// Now add both to our saved copy of the tree head log.
			a.MutationLogTreeHeads = append(a.MutationLogTreeHeads, headHash)
			a.MapTreeHeads = append(a.MapTreeHeads, rh)

			// Finally, if we actually made a change (ie the mutation did something)
			// then call the underlying audit function provided by the client.
			if a.MapAuditFunction != nil && !bytes.Equal(lastRootHash, rh) {
				err = a.MapAuditFunction(ctx, idx, mutation.Key, mutation.Value)
				if err != nil {
					return err
				}
				return nil
			}

			// Save for next time
			lastRootHash = rh

			return nil
		})
		if err != nil {
			return err
		}

		// Save off mutation log for next run
		a.MutLogHead = mutLogHead
		a.Size = a.MutLogHead.TreeSize
	}

	if size > a.Size {
		return util.ErrVerificationFailed
	}

	return nil
}

// CheckTreeHeadEntry is the audit function that checks the actual tree head is correct
func (a *auditState) CheckTreeHeadEntry(ctx context.Context, idx int64, entry *pb.LeafData) error {
	// Step 0, are we a valid JSON hash?
	err := util.ValidateJSONLeafData(ctx, entry)
	if err != nil {
		return err
	}

	// Get the tree head data
	// Decode it into standard structure
	var mth pb.MapTreeHashResponse
	err = json.Unmarshal(entry.ExtraData, &mth)
	if err != nil {
		return err
	}

	// Advance the state of the auditor to at least this size
	err = a.ProcessUntilAtLeast(ctx, mth.MutationLog.TreeSize)
	if err != nil {
		return err
	}

	// Check map root hash (subtract 1 from index since size 1 is the first meaningful)
	if !bytes.Equal(a.MapTreeHeads[mth.MutationLog.TreeSize-1], mth.RootHash) {
		return util.ErrVerificationFailed
	}

	// Check mutation log hash (subtract 1 from index since size 1 is the first meaningful)
	if !bytes.Equal(a.MutationLogTreeHeads[mth.MutationLog.TreeSize-1], mth.MutationLog.RootHash) {
		return util.ErrVerificationFailed
	}

	// All good
	return nil
}
