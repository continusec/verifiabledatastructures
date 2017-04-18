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

package client

import (
	"bytes"
	"time"

	"github.com/continusec/verifiabledatastructures/pb"

	"golang.org/x/net/context"
)

// VerifyInclusion will fetch a proof the the specified MerkleTreeHash is included in the
// log and verify that it can produce the root hash in the specified LogTreeHead.
func (log *VerifiableLog) VerifyInclusion(head *pb.LogTreeHashResponse, leaf []byte) error {
	proof, err := log.InclusionProof(head.TreeSize, leaf)
	if err != nil {
		return err
	}

	err = VerifyLogInclusionProof(proof, leaf, head)
	if err != nil {
		return err
	}

	// All good
	return nil
}

// VerifyConsistency takes two tree heads, retrieves a consistency proof, verifies it,
// and returns the result. The two tree heads may be in either order (even equal), but both must be greater than zero and non-nil.
func (log *VerifiableLog) VerifyConsistency(a, b *pb.LogTreeHashResponse) error {
	if a == nil || b == nil || a.TreeSize <= 0 || b.TreeSize <= 0 {
		return ErrVerificationFailed
	}

	// Special case being equal
	if a.TreeSize == b.TreeSize {
		if !bytes.Equal(a.RootHash, b.RootHash) {
			return ErrVerificationFailed
		}
		// All good
		return nil
	}

	// If wrong order, swap 'em
	if a.TreeSize > b.TreeSize {
		a, b = b, a
	}

	proof, err := log.ConsistencyProof(a.TreeSize, b.TreeSize)
	if err != nil {
		return err
	}
	err = VerifyLogConsistencyProof(proof, a, b)
	if err != nil {
		return err
	}

	// All good
	return nil
}

// BlockUntilPresent blocks until the log is able to produce a LogTreeHead that includes the
// specified MerkleTreeLeaf. This polls TreeHead() and InclusionProof() until such time as a new
// tree hash is produced that includes the given MerkleTreeLeaf. Exponential back-off is used
// when no new tree hash is available.
//
// This is intended for test use.
func (log *VerifiableLog) BlockUntilPresent(leaf []byte) (*pb.LogTreeHashResponse, error) {
	lastHead := int64(-1)
	timeToSleep := time.Second
	for {
		lth, err := log.TreeHead(Head)
		if err != nil {
			return nil, err
		}
		if lth.TreeSize > lastHead {
			lastHead = lth.TreeSize
			err = log.VerifyInclusion(lth, leaf)
			switch err {
			case nil: // we found it
				return lth, nil
			case ErrNotFound:
				// no good, continue
			default:
				return nil, err
			}
			// since we got a new tree head, reset sleep time
			timeToSleep = time.Second
		} else {
			// no luck, snooze a bit longer
			timeToSleep *= 2
		}
		time.Sleep(timeToSleep)
	}
}

// VerifiedLatestTreeHead calls VerifiedTreeHead() with Head to fetch the latest tree head,
// and additionally verifies that it is newer than the previously passed tree head.
// For first use, pass nil to skip consistency checking.
func (log *VerifiableLog) VerifiedLatestTreeHead(prev *pb.LogTreeHashResponse) (*pb.LogTreeHashResponse, error) {
	head, err := log.VerifiedTreeHead(prev, Head)
	if err != nil {
		return nil, err
	}

	// If "newest" is actually older (but consistent), catch and return the previous. While the log should not
	// normally go backwards, it is reasonable that a distributed system may not be entirely up to date immediately.
	if prev != nil {
		if head.TreeSize <= prev.TreeSize {
			return prev, nil
		}
	}

	// All good
	return head, nil
}

// VerifiedTreeHead is a utility method to fetch a LogTreeHead and verifies that it is consistent with
// a tree head earlier fetched and persisted. For first use, pass nil for prev, which will
// bypass consistency proof checking. Tree size may be older or newer than the previous head value.
//
// Clients typically use VerifyLatestTreeHead().
func (log *VerifiableLog) VerifiedTreeHead(prev *pb.LogTreeHashResponse, treeSize int64) (*pb.LogTreeHashResponse, error) {
	// special case returning the value we already have
	if treeSize != 0 && prev != nil && prev.TreeSize == treeSize {
		return prev, nil
	}

	head, err := log.TreeHead(treeSize)
	if err != nil {
		return nil, err
	}

	if prev != nil {
		err = log.VerifyConsistency(prev, head)
		if err != nil {
			return nil, err
		}
	}

	return head, nil
}

// VerifySuppliedInclusionProof is a utility method that fetches any required tree heads that are needed
// to verify a supplied log inclusion proof. Additionally it will ensure that any fetched tree heads are consistent
// with any prior supplied LogTreeHead (which may be nil, to skip consistency checks).
//
// Upon success, the LogTreeHead returned is the one used to verify the inclusion proof - it may be newer or older than the one passed in.
// In either case, it will have been verified as consistent.
func (log *VerifiableLog) VerifySuppliedInclusionProof(prev *pb.LogTreeHashResponse, proof *pb.LogInclusionProofResponse, leaf []byte) (*pb.LogTreeHashResponse, error) {
	headForInclProof, err := log.VerifiedTreeHead(prev, proof.TreeSize)
	if err != nil {
		return nil, err
	}

	err = VerifyLogInclusionProof(proof, leaf, headForInclProof)
	if err != nil {
		return nil, err
	}

	// all clear
	return headForInclProof, nil
}

// VerifyEntries is a utility method for auditors that wish to audit the full content of
// a log, as well as the log operation. This method will retrieve all entries in batch from
// the log between the passed in prev and head LogTreeHeads, and ensure that the root hash in head can be confirmed to accurately represent
// the contents of all of the log entries retrieved. To start at entry zero, pass nil for prev, which will also bypass consistency proof checking. Head must not be nil.
func (log *VerifiableLog) VerifyEntries(ctx context.Context, prev *pb.LogTreeHashResponse, head *pb.LogTreeHashResponse, auditFunc LogAuditFunction) error {
	if head == nil {
		return ErrNilTreeHead
	}

	if prev != nil && head.TreeSize <= prev.TreeSize {
		return nil
	}

	if head.TreeSize < 1 {
		return nil
	}

	merkleTreeStack := make([][]byte, 0)
	idx := int64(0)
	if prev != nil && prev.TreeSize > 0 {
		idx = prev.TreeSize
		p, err := log.InclusionProofByIndex(prev.TreeSize+1, prev.TreeSize)
		if err != nil {
			return err
		}
		var firstHash []byte
		for _, b := range p.AuditPath {
			if firstHash == nil {
				firstHash = b
			} else {
				firstHash = NodeMerkleTreeHash(b, firstHash)
			}
		}
		if !bytes.Equal(firstHash, prev.RootHash) {
			return ErrVerificationFailed
		}
		if len(firstHash) != 32 {
			return ErrVerificationFailed
		}
		for i := len(p.AuditPath) - 1; i >= 0; i-- {
			merkleTreeStack = append(merkleTreeStack, p.AuditPath[i])
		}
	}

	ourCtx, canc := context.WithCancel(ctx)
	defer canc()
	for entry := range log.Entries(ourCtx, idx, head.TreeSize) {
		// audit
		if auditFunc != nil {
			err := auditFunc(ctx, idx, entry)
			if err != nil {
				return err
			}
		}

		mtlHash := LeafMerkleTreeHash(entry.GetLeafInput())

		merkleTreeStack = append(merkleTreeStack, mtlHash)
		for z := idx; (z & 1) == 1; z >>= 1 {
			merkleTreeStack = append(merkleTreeStack[:len(merkleTreeStack)-2], NodeMerkleTreeHash(merkleTreeStack[len(merkleTreeStack)-2], merkleTreeStack[len(merkleTreeStack)-1]))
		}

		idx++
	}

	if idx != head.TreeSize {
		return ErrNotAllEntriesReturned
	}

	if len(merkleTreeStack) == 0 {
		return ErrVerificationFailed
	}

	headHash := merkleTreeStack[len(merkleTreeStack)-1]
	for z := len(merkleTreeStack) - 2; z >= 0; z-- {
		headHash = NodeMerkleTreeHash(merkleTreeStack[z], headHash)
	}

	if !bytes.Equal(headHash, head.RootHash) {
		return ErrVerificationFailed
	}
	if len(headHash) != 32 {
		return ErrVerificationFailed
	}

	// all clear
	return nil
}
