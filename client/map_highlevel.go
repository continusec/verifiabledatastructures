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
	"time"

	"github.com/continusec/verifiabledatastructures/pb"

	"golang.org/x/net/context"
)

// VerifiedGet gets the value for the given key in the specified MapTreeState, and verifies that it is
// included in the MapTreeHead (wrapped by the MapTreeState) before returning.
func (vmap *VerifiableMap) VerifiedGet(key []byte, mapHead *MapTreeState) (*pb.LeafData, error) {
	proof, err := vmap.Get(key, mapHead.TreeSize())
	if err != nil {
		return nil, err
	}
	err = VerifyMapInclusionProof(proof, key, mapHead.MapTreeHead)
	if err != nil {
		return nil, err
	}
	return proof.Value, nil
}

// BlockUntilSize blocks until the map has caught up to a certain size. This polls
// TreeHead() until such time as a new tree hash is produced that is of at least this
// size.
//
// This is intended for test use.
func (vmap *VerifiableMap) BlockUntilSize(treeSize int64) (*pb.MapTreeHashResponse, error) {
	lastHead := int64(-1)
	timeToSleep := time.Second
	for {
		lth, err := vmap.TreeHead(Head)
		if err != nil {
			return nil, err
		}
		if lth.MutationLog.TreeSize >= treeSize {
			return lth, nil
		}
		if lth.MutationLog.TreeSize > lastHead {
			lastHead = lth.MutationLog.TreeSize
			// since we got a new tree head, reset sleep time
			timeToSleep = time.Second
		} else {
			// no luck, snooze a bit longer
			timeToSleep *= 2
		}
		time.Sleep(timeToSleep)
	}
}

// VerifiedLatestMapState fetches the latest MapTreeState, verifies it is consistent with,
// and newer than, any previously passed state.
func (vmap *VerifiableMap) VerifiedLatestMapState(prev *MapTreeState) (*MapTreeState, error) {
	head, err := vmap.VerifiedMapState(prev, Head)
	if err != nil {
		return nil, err
	}

	if prev != nil {
		// this shouldn't go backwards, but perhaps in a distributed system not all nodes are up to date immediately,
		// so we won't consider it an error, but will return the old value in such a case.
		if head.TreeSize() <= prev.TreeSize() {
			return prev, nil
		}
	}

	// all good
	return head, nil
}

// VerifiedMapState returns a wrapper for the MapTreeHead for a given tree size, along with
// a LogTreeHead for the TreeHeadLog that has been verified to contain this map tree head.
// The value returned by this will have been proven to be consistent with any passed prev value.
// Note that the TreeHeadLogTreeHead returned may differ between calls, even for the same treeSize,
// as all future LogTreeHeads can also be proven to contain the MapTreeHead.
//
// Typical clients that only need to access current data will instead use VerifiedLatestMapState()
// Can return nil, nil if the map is empty (and prev was nil)
func (vmap *VerifiableMap) VerifiedMapState(prev *MapTreeState, treeSize int64) (*MapTreeState, error) {
	if treeSize != 0 && prev != nil && prev.TreeSize() == treeSize {
		return prev, nil
	}

	// Get latest map head
	mapHead, err := vmap.TreeHead(treeSize)
	if err != nil {
		return nil, err
	}

	// Short-cut: If prev is nil, and we have no size yet, then we are nil too
	// since while a map head may be valid, the logs can't be.
	if prev == nil && mapHead.MutationLog.TreeSize == 0 {
		return nil, nil
	}

	// If we have a previous state, then make sure both logs are consistent with it
	if prev != nil {
		// Make sure that the mutation log is consistent with what we had
		err = vmap.MutationLog().VerifyConsistency(prev.MapTreeHead.MutationLog, mapHead.MutationLog)
		if err != nil {
			return nil, err
		}
	}

	// Get the latest tree head for the tree head log
	var prevThlth, thlth *pb.LogTreeHashResponse
	if prev != nil {
		prevThlth = prev.TreeHeadLogTreeHead
	}

	// Have we verified ourselves yet?
	verifiedInTreeHeadLog := false

	// If we already have a tree head that is the size of our map, then we
	// probably don't need a new one, so try that first.
	if prevThlth != nil && prevThlth.TreeSize >= mapHead.MutationLog.TreeSize {
		lh, err := CreateJSONLeafDataFromObject(mapHead)
		if err != nil {
			return nil, err
		}
		err = vmap.TreeHeadLog().VerifyInclusion(prevThlth, lh.LeafInput)
		if err == nil {
			verifiedInTreeHeadLog = true
			thlth = prevThlth
		} // but it's ok if we fail, since try again below
	}

	// If we weren't able to take a short-cut above, go back to normal processing:
	if !verifiedInTreeHeadLog {
		// Get new tree head
		thlth, err = vmap.TreeHeadLog().VerifiedLatestTreeHead(prevThlth)
		if err != nil {
			return nil, err
		}

		// And make sure we are in it
		li, err := CreateJSONLeafDataFromObject(mapHead)
		if err != nil {
			return nil, err
		}
		err = vmap.TreeHeadLog().VerifyInclusion(thlth, LeafMerkleTreeHash(li.LeafInput))
		if err != nil {
			return nil, err
		}
	}

	// All good
	return &MapTreeState{
		MapTreeHead:         mapHead,
		TreeHeadLogTreeHead: thlth,
	}, nil
}

// VerifyMap (Experimental API surface, likely to change) is a utility method for auditors
// that wish to audit the full content of a map, as well as the map operation. This method
// will verify every entry in the TreeHeadLogTreeHead between prev and head - and to do so
// will retrieve *all* mutation entries from the underlying mutation log, and play them
// forward in an in-memory map copy.
//
// In addition to verifying the correct operation of the map itself, a client also specifies
// an auditFunc that is called for each set value operation that results in a change to the
// map itself. As such a client can also verify any property desired around the actual
// key/values themselves that are being manipulated. Note that not every mutation will result
// in a call to auditFunc - operations that result in no change to the map will not call
// the audit function.
//
// To verify all every log tree head entry, pass nil for prev, which will also bypass consistency proof checking. Head must not be nil.
//
// Example usage:
//
//	latestMapState, err := vmap.VerifiedLatestMapState(nil)
//	if err != nil {
//		...
//	}
//
//	err = vmap.VerifyMap(ctx, nil, latestMapState, continusec.RedactedJsonEntryFactory, func(ctx context.Context, idx int64, key []byte, value continusec.VerifiableEntry) error {
//		... // verify anything you like about the content
//		return nil
//	})
//	if err != nil {
//		...
//	}
//
// While suitable for small to medium maps, this requires the entire map be built in-memory
// which may not be suitable for larger systems that will have more complex requirements.
func (vmap *VerifiableMap) VerifyMap(ctx context.Context, prev *MapTreeState, head *MapTreeState, leafFunc LeafDataAuditFunction, auditFunc MapAuditFunction) error {
	var prevLth *pb.LogTreeHashResponse
	if prev != nil {
		prevLth = prev.TreeHeadLogTreeHead
	}

	if head == nil {
		return ErrNilTreeHead
	}

	return vmap.TreeHeadLog().VerifyEntries(ctx, prevLth, head.TreeHeadLogTreeHead, (&auditState{
		Map:                   vmap,
		MapAuditFunction:      auditFunc,
		LeafDataAuditFunction: leafFunc,
	}).CheckTreeHeadEntry)
}
