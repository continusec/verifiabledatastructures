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
	"errors"

	"golang.org/x/net/context"
)

// Head can be used where tree sizes are accepted to represent the latest tree size.
// Most typically this is used with TreeHead() calls where the latest tree size is not
// yet known.
const Head = int64(0)

var (
	// ErrNotAuthorized is returned when the request is understood, but there are no API access
	// rules specified that allow such access. Check the API Key and account number passed are correct,
	// and that you are trying to access the log/map with the appropriate name.
	//
	// Also have an administrator check the "Billing" page to ensure the billing settings are up to date, as this
	// error can also be indicative of an expired free trial, or an expired credit card.
	ErrNotAuthorized = errors.New("Unauthorized request. Check API key, account, log name and also billing settings.")

	// ErrInternalError is an unspecified error. Contact info@continusec.com if these persist.
	ErrInternalError = errors.New("Unspecified error.")

	// ErrInvalidRange is returned when an invalid index is specified in the request, for example
	// if a tree size is specified that is greater than the current size of the tree / map.
	ErrInvalidRange = errors.New("Invalid range requested.")

	// ErrNotFound is returned when the request is understood and authorized, however the underlying
	// map/log cannot be found. Check the name of the map/log and verify that you have already created it.
	// This is also returned if an inclusion proof is requested for a non-existent element.
	ErrNotFound = errors.New("Can't find log/map/entry. Check the log/map/entry is created.")

	// Verification of proof failed.
	ErrVerificationFailed = errors.New("ErrVerificationFailed")

	// Object may already exist
	ErrObjectConflict = errors.New("ErrObjectConflict")

	// A nil tree head was unexpectedly passed as input
	ErrNilTreeHead = errors.New("ErrNilTreeHead")

	// ErrNotAllEntriesReturned can occur if Json is requested, but the data on the server was
	// not stored in that manner. If in doubt, RawDataEntryFactory will always succeed regardless of input format.
	ErrNotAllEntriesReturned = errors.New("ErrNotAllEntriesReturned")

	// ErrInvalidJSON occurs when there is invalid JSON
	ErrInvalidJSON = errors.New("ErrInvalidJSON")
)

// LogAuditFunction is a function that is called for all matching log entries.
// Return non-nil to stop the audit.
type LogAuditFunction func(ctx context.Context, idx int64, entry VerifiableEntry) error

// MerkleTreeLeaf is an interface to represent any object that a Merkle Tree Leaf can be calculated for.
// This includes RawDataEntry, JsonEntry, RedactedJsonEntry, AddEntryResponse and MapHead.
type MerkleTreeLeaf interface {
	// LeafHash() returns the leaf hash for this object.
	LeafHash() ([]byte, error)
}

// UploadableEntry is an interface to represent an entry type that can be uploaded as a log entry or map value.
// This includes RawDataEntry, JsonEntry, RedactableJsonEntry.
type UploadableEntry interface {
	// DataForStorage is intended for execution server-side. It returns:
	// MTLHash Input, Storage data, error
	DataForStorage() ([]byte, []byte, error)

	// DataForUpload returns the data that should be uploaded
	DataForUpload() ([]byte, error)
	// Format returns the format suffix that should be be appended to the PUT/POST API call
	Format() string
}

// VerifiableEntry is an interface that represents an entry returned from the log
type VerifiableEntry interface {
	// LeafHash() returns the leaf hash for this object.
	LeafHash() ([]byte, error)
	// Data() returns data suitable for downstream processing of this entry by your application.
	Data() ([]byte, error)
}

// VerifiableEntryFactory is an for instantiation of VerifiableEntries from bytes.
type VerifiableEntryFactory interface {
	// CreateFromBytes creates a new VerifiableEntry given these bytes from the server.
	CreateFromBytes(b []byte) (VerifiableEntry, error)
	// Format returns the format suffix that should be be appended to the GET call.
	Format() string
}

// Service can either be a client, or server directly
type Service interface {
	Account(id string, apiKey string) Account
}

// Account is used to access your Continusec account.
type Account interface {
	// VerifiableMap returns an object representing a Verifiable Map. This function simply
	// returns a pointer to an object that can be used to interact with the Map, and won't
	// by itself cause any API calls to be generated.
	VerifiableMap(name string) VerifiableMap

	// VerifiableLog returns an object representing a Verifiable Log. This function simply
	// returns a pointer to an object that can be used to interact with the Log, and won't
	// by itself cause any API calls to be generated.
	VerifiableLog(name string) VerifiableLog

	// ListLogs returns a list of logs held by the account
	ListLogs() ([]VerifiableLog, error)

	// ListMaps returns a list of maps held by the account
	ListMaps() ([]VerifiableMap, error)
}

// VerifiableLog is an object used to interact with Verifiable Logs. To construct this
// object, call NewClient(...).VerifiableLog("logname")
type VerifiableLog interface {
	// Create will send an API call to create a new log with the name specified when the
	// verifiableLogImpl object was instantiated.
	Create() error

	// Destroy will send an API call to delete this log - this operation removes it permanently,
	// and renders the name unusable again within the same account, so please use with caution.
	Destroy() error

	// Add will send an API call to add the specified entry to the log. If the exact entry
	// already exists in the log, it will not be added a second time.
	// Returns an AddEntryResponse which includes the leaf hash, whether it is a duplicate or not. Note that the
	// entry is sequenced in the underlying log in an asynchronous fashion, so the tree size
	// will not immediately increase, and inclusion proof checks will not reflect the new entry
	// until it is sequenced.
	Add(e UploadableEntry) (*AddEntryResponse, error)

	// TreeHead returns tree root hash for the log at the given tree size. Specify continusec.Head
	// to receive a root hash for the latest tree size.
	TreeHead(treeSize int64) (*LogTreeHead, error)

	// InclusionProof will return a proof the the specified MerkleTreeLeaf is included in the
	// log. The proof consists of the index within the log that the entry is stored, and an
	// audit path which returns the corresponding leaf nodes that can be applied to the input
	// leaf hash to generate the root tree hash for the log.
	//
	// Most clients instead use VerifyInclusion which additionally verifies the returned proof.
	InclusionProof(treeSize int64, leaf MerkleTreeLeaf) (*LogInclusionProof, error)

	// InclusionProofByIndex will return an inclusion proof for a specified tree size and leaf index.
	// This is not used by typical clients, however it can be useful for certain audit operations and debugging tools.
	// The LogInclusionProof returned by this method will not have the LeafHash filled in and as such will fail to verify.
	//
	// Typical clients will instead use VerifyInclusionProof().
	InclusionProofByIndex(treeSize, leafIndex int64) (*LogInclusionProof, error)

	// ConsistencyProof returns an audit path which contains the set of Merkle Subtree hashes
	// that demonstrate how the root hash is calculated for both the first and second tree sizes.
	//
	// Most clients instead use VerifyInclusionProof which additionally verifies the returned proof.
	ConsistencyProof(first, second int64) (*LogConsistencyProof, error)

	// Entry returns the entry stored for the given index using the passed in factory to instantiate the entry.
	// This is normally one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
	// If the entry was stored using one of the ObjectHash formats, then the data returned by a RawDataEntryFactory,
	// then the object hash itself is returned as the contents. To get the data itself, use JsonEntryFactory.
	Entry(idx int64, factory VerifiableEntryFactory) (VerifiableEntry, error)

	// Entries batches requests to fetch entries from the server and returns a channel with the data
	// for each entry. Close the context passed to terminate early if desired. If an error is
	// encountered, the channel will be closed early before all items are returned.
	//
	// factory is normally one of one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
	Entries(ctx context.Context, start, end int64, factory VerifiableEntryFactory) <-chan VerifiableEntry

	// Name returns the name of the log
	Name() string
}

type VerifiableMap interface {
	// MutationLog returns a pointer to the underlying Verifiable Log that represents
	// a log of mutations to this map. Since this Verifiable Log is managed by this map,
	// the log returned cannot be directly added to (to mutate, call Set and Delete methods
	// on the map), however all read-only functions are present.
	MutationLog() VerifiableLog

	// TreeHeadLog returns a pointer to the underlying Verifiable Log that represents
	// a log of tree heads generated by this map. Since this Verifiable Map is managed by this map,
	// the log returned cannot be directly added to however all read-only functions are present.
	TreeHeadLog() VerifiableLog

	// Create will send an API call to create a new map with the name specified when the
	// VerifiableMap object was instantiated.
	Create() error

	// Destroy will send an API call to delete this map - this operation removes it permanently,
	// and renders the name unusable again within the same account, so please use with caution.
	Destroy() error

	// Get will return the value for the given key at the given treeSize. Pass continusec.Head
	// to always get the latest value. factory is normally one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
	//
	// Clients normally instead call VerifiedGet() with a MapTreeHead returned by VerifiedLatestMapState as this will also perform verification of inclusion.
	Get(key []byte, treeSize int64, factory VerifiableEntryFactory) (*MapInclusionProof, error)

	// Set will generate a map mutation to set the given value for the given key.
	// While this will return quickly, the change will be reflected asynchronously in the map.
	// Returns an AddEntryResponse which contains the leaf hash for the mutation log entry.
	Set(key []byte, value UploadableEntry) (*AddEntryResponse, error)

	// Update will generate a map mutation to set the given value for the given key, conditional on the
	// previous leaf hash being that specified by previousLeaf.
	// While this will return quickly, the change will be reflected asynchronously in the map.
	// Returns an AddEntryResponse which contains the leaf hash for the mutation log entry.
	Update(key []byte, value UploadableEntry, previousLeaf MerkleTreeLeaf) (*AddEntryResponse, error)

	// Delete will set generate a map mutation to delete the value for the given key. Calling Delete
	// is equivalent to calling Set with an empty value.
	// While this will return quickly, the change will be reflected asynchronously in the map.
	// Returns an AddEntryResponse which contains the leaf hash for the mutation log entry.
	Delete(key []byte) (*AddEntryResponse, error)

	// TreeHead returns map root hash for the map at the given tree size. Specify continusec.Head
	// to receive a root hash for the latest tree size.
	TreeHead(treeSize int64) (*MapTreeHead, error)

	// Name returns the name of the map
	Name() string
}
