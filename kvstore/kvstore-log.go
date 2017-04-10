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

package kvstore

import (
	"golang.org/x/net/context"

	"github.com/continusec/go-client/continusec"
)

const (
	logTypeUser        = 0
	logTypeMapMutation = 1
	logTypeMapTreeHead = 2
)

type bbLog struct {
	account *bbAccount
	name    string
	logType int
}

// Create will send an API call to create a new log with the name specified when the
// verifiableLogImpl object was instantiated.
func (l *bbLog) Create() error {
	return ErrNotImplemented
}

// Destroy will send an API call to delete this log - this operation removes it permanently,
// and renders the name unusable again within the same account, so please use with caution.
func (l *bbLog) Destroy() error {
	return ErrNotImplemented
}

// Add will send an API call to add the specified entry to the log. If the exact entry
// already exists in the log, it will not be added a second time.
// Returns an AddEntryResponse which includes the leaf hash, whether it is a duplicate or not. Note that the
// entry is sequenced in the underlying log in an asynchronous fashion, so the tree size
// will not immediately increase, and inclusion proof checks will not reflect the new entry
// until it is sequenced.
func (l *bbLog) Add(e continusec.UploadableEntry) (*continusec.AddEntryResponse, error) {
	return nil, ErrNotImplemented
}

// TreeHead returns tree root hash for the log at the given tree size. Specify continusec.Head
// to receive a root hash for the latest tree size.
func (l *bbLog) TreeHead(treeSize int64) (*continusec.LogTreeHead, error) {
	return nil, ErrNotImplemented
}

// InclusionProof will return a proof the the specified MerkleTreeLeaf is included in the
// log. The proof consists of the index within the log that the entry is stored, and an
// audit path which returns the corresponding leaf nodes that can be applied to the input
// leaf hash to generate the root tree hash for the log.
//
// Most clients instead use VerifyInclusion which additionally verifies the returned proof.
func (l *bbLog) InclusionProof(treeSize int64, leaf continusec.MerkleTreeLeaf) (*continusec.LogInclusionProof, error) {
	return nil, ErrNotImplemented
}

// VerifyInclusion will fetch a proof the the specified MerkleTreeHash is included in the
// log and verify that it can produce the root hash in the specified LogTreeHead.
func (l *bbLog) VerifyInclusion(head *continusec.LogTreeHead, leaf continusec.MerkleTreeLeaf) error {
	return ErrNotImplemented
}

// InclusionProofByIndex will return an inclusion proof for a specified tree size and leaf index.
// This is not used by typical clients, however it can be useful for certain audit operations and debugging tools.
// The LogInclusionProof returned by this method will not have the LeafHash filled in and as such will fail to verify.
//
// Typical clients will instead use VerifyInclusionProof().
func (l *bbLog) InclusionProofByIndex(treeSize, leafIndex int64) (*continusec.LogInclusionProof, error) {
	return nil, ErrNotImplemented
}

// ConsistencyProof returns an audit path which contains the set of Merkle Subtree hashes
// that demonstrate how the root hash is calculated for both the first and second tree sizes.
//
// Most clients instead use VerifyInclusionProof which additionally verifies the returned proof.
func (l *bbLog) ConsistencyProof(first, second int64) (*continusec.LogConsistencyProof, error) {
	return nil, ErrNotImplemented
}

// VerifyConsistency takes two tree heads, retrieves a consistency proof, verifies it,
// and returns the result. The two tree heads may be in either order (even equal), but both must be greater than zero and non-nil.
func (l *bbLog) VerifyConsistency(a, b *continusec.LogTreeHead) error {
	return ErrNotImplemented
}

// Entry returns the entry stored for the given index using the passed in factory to instantiate the entry.
// This is normally one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
// If the entry was stored using one of the ObjectHash formats, then the data returned by a RawDataEntryFactory,
// then the object hash itself is returned as the contents. To get the data itself, use JsonEntryFactory.
func (l *bbLog) Entry(idx int64, factory continusec.VerifiableEntryFactory) (continusec.VerifiableEntry, error) {
	return nil, ErrNotImplemented
}

// Entries batches requests to fetch entries from the server and returns a channel with the data
// for each entry. Close the context passed to terminate early if desired. If an error is
// encountered, the channel will be closed early before all items are returned.
//
// factory is normally one of one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
func (l *bbLog) Entries(ctx context.Context, start, end int64, factory continusec.VerifiableEntryFactory) <-chan continusec.VerifiableEntry {
	panic(ErrNotImplemented)
}

// BlockUntilPresent blocks until the log is able to produce a LogTreeHead that includes the
// specified MerkleTreeLeaf. This polls TreeHead() and InclusionProof() until such time as a new
// tree hash is produced that includes the given MerkleTreeLeaf. Exponential back-off is used
// when no new tree hash is available.
//
// This is intended for test use.
func (l *bbLog) BlockUntilPresent(leaf continusec.MerkleTreeLeaf) (*continusec.LogTreeHead, error) {
	return nil, ErrNotImplemented
}

// VerifiedLatestTreeHead calls VerifiedTreeHead() with Head to fetch the latest tree head,
// and additionally verifies that it is newer than the previously passed tree head.
// For first use, pass nil to skip consistency checking.
func (l *bbLog) VerifiedLatestTreeHead(prev *continusec.LogTreeHead) (*continusec.LogTreeHead, error) {
	return nil, ErrNotImplemented
}

// VerifiedTreeHead is a utility method to fetch a LogTreeHead and verifies that it is consistent with
// a tree head earlier fetched and persisted. For first use, pass nil for prev, which will
// bypass consistency proof checking. Tree size may be older or newer than the previous head value.
//
// Clients typically use VerifyLatestTreeHead().
func (l *bbLog) VerifiedTreeHead(prev *continusec.LogTreeHead, treeSize int64) (*continusec.LogTreeHead, error) {
	return nil, ErrNotImplemented
}

// VerifySuppliedInclusionProof is a utility method that fetches any required tree heads that are needed
// to verify a supplied log inclusion proof. Additionally it will ensure that any fetched tree heads are consistent
// with any prior supplied LogTreeHead (which may be nil, to skip consistency checks).
//
// Upon success, the LogTreeHead returned is the one used to verify the inclusion proof - it may be newer or older than the one passed in.
// In either case, it will have been verified as consistent.
func (l *bbLog) VerifySuppliedInclusionProof(prev *continusec.LogTreeHead, proof *continusec.LogInclusionProof) (*continusec.LogTreeHead, error) {
	return nil, ErrNotImplemented
}

// VerifyEntries is a utility method for auditors that wish to audit the full content of
// a log, as well as the log operation. This method will retrieve all entries in batch from
// the log between the passed in prev and head LogTreeHeads, and ensure that the root hash in head can be confirmed to accurately represent
// the contents of all of the log entries retrieved. To start at entry zero, pass nil for prev, which will also bypass consistency proof checking. Head must not be nil.
func (l *bbLog) VerifyEntries(ctx context.Context, prev *continusec.LogTreeHead, head *continusec.LogTreeHead, factory continusec.VerifiableEntryFactory, auditFunc continusec.LogAuditFunction) error {
	return ErrNotImplemented
}

// Name returns the name of the log
func (l *bbLog) Name() string {
	switch l.logType {
	case logTypeUser:
		return l.name
	case logTypeMapMutation:
		return l.name + " (mutation log)"
	case logTypeMapTreeHead:
		return l.name + " (tree head log)"
	default:
		return ""
	}
}
