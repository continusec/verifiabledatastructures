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
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/net/context"
)

// verifiableLogImpl is an object used to interact with Verifiable Logs. To construct this
// object, call NewClient(...).verifiableLogImpl("logname")
type verifiableLogImpl struct {
	Client  *Client
	LogName string
}

func (self *verifiableLogImpl) Name() string {
	return self.LogName
}

// Create will send an API call to create a new log with the name specified when the
// verifiableLogImpl object was instantiated.
func (self *verifiableLogImpl) Create() error {
	_, _, err := self.Client.MakeRequest("PUT", "", nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// Destroy will send an API call to delete this log - this operation removes it permanently,
// and renders the name unusable again within the same account, so please use with caution.
func (self *verifiableLogImpl) Destroy() error {
	_, _, err := self.Client.MakeRequest("DELETE", "", nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// Add will send an API call to add the specified entry to the log. If the exact entry
// already exists in the log, it will not be added a second time.
// Returns an AddEntryResponse which includes the leaf hash, whether it is a duplicate or not. Note that the
// entry is sequenced in the underlying log in an asynchronous fashion, so the tree size
// will not immediately increase, and inclusion proof checks will not reflect the new entry
// until it is sequenced.
func (self *verifiableLogImpl) Add(e UploadableEntry) (*AddEntryResponse, error) {
	data, err := e.DataForUpload()
	if err != nil {
		return nil, err
	}
	contents, _, err := self.Client.MakeRequest("POST", "/entry"+e.Format(), data, nil)
	if err != nil {
		return nil, err
	}
	var aer JSONAddEntryResponse
	err = json.Unmarshal(contents, &aer)
	if err != nil {
		return nil, err
	}
	return &AddEntryResponse{EntryLeafHash: aer.Hash}, nil
}

// TreeHead returns tree root hash for the log at the given tree size. Specify continusec.Head
// to receive a root hash for the latest tree size.
func (self *verifiableLogImpl) TreeHead(treeSize int64) (*LogTreeHead, error) {
	contents, _, err := self.Client.MakeRequest("GET", fmt.Sprintf("/tree/%d", treeSize), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr JSONLogTreeHeadResponse
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &LogTreeHead{
		TreeSize: cr.TreeSize,
		RootHash: cr.Hash,
	}, nil
}

// InclusionProof will return a proof the the specified MerkleTreeLeaf is included in the
// log. The proof consists of the index within the log that the entry is stored, and an
// audit path which returns the corresponding leaf nodes that can be applied to the input
// leaf hash to generate the root tree hash for the log.
//
// Most clients instead use VerifyInclusion which additionally verifies the returned proof.
func (self *verifiableLogImpl) InclusionProof(treeSize int64, leaf MerkleTreeLeaf) (*LogInclusionProof, error) {
	mtlHash, err := leaf.LeafHash()
	if err != nil {
		return nil, err
	}
	contents, _, err := self.Client.MakeRequest("GET", fmt.Sprintf("/tree/%d/inclusion/h/%s", treeSize, hex.EncodeToString(mtlHash)), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr JSONInclusionProofResponse
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &LogInclusionProof{
		LeafHash:  mtlHash,
		LeafIndex: cr.Number,
		AuditPath: cr.Proof,
		TreeSize:  cr.TreeSize,
	}, nil
}

// InclusionProofByIndex will return an inclusion proof for a specified tree size and leaf index.
// This is not used by typical clients, however it can be useful for certain audit operations and debugging tools.
// The LogInclusionProof returned by this method will not have the LeafHash filled in and as such will fail to verify.
//
// Typical clients will instead use VerifyInclusionProof().
func (self *verifiableLogImpl) InclusionProofByIndex(treeSize, leafIndex int64) (*LogInclusionProof, error) {
	contents, _, err := self.Client.MakeRequest("GET", fmt.Sprintf("/tree/%d/inclusion/%d", treeSize, leafIndex), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr JSONInclusionProofResponse
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &LogInclusionProof{
		LeafHash:  nil,
		LeafIndex: cr.Number,
		AuditPath: cr.Proof,
		TreeSize:  cr.TreeSize,
	}, nil
}

// ConsistencyProof returns an audit path which contains the set of Merkle Subtree hashes
// that demonstrate how the root hash is calculated for both the first and second tree sizes.
//
// Most clients instead use VerifyInclusionProof which additionally verifies the returned proof.
func (self *verifiableLogImpl) ConsistencyProof(first, second int64) (*LogConsistencyProof, error) {
	contents, _, err := self.Client.MakeRequest("GET", fmt.Sprintf("/tree/%d/consistency/%d", second, first), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr JSONConsistencyProofResponse
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &LogConsistencyProof{
		AuditPath:  cr.Proof,
		FirstSize:  cr.First,
		SecondSize: cr.Second,
	}, nil
}

// Entry returns the entry stored for the given index using the passed in factory to instantiate the entry.
// This is normally one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
// If the entry was stored using one of the ObjectHash formats, then the data returned by a RawDataEntryFactory,
// then the object hash itself is returned as the contents. To get the data itself, use JsonEntryFactory.
func (self *verifiableLogImpl) Entry(idx int64, factory VerifiableEntryFactory) (VerifiableEntry, error) {
	contents, _, err := self.Client.MakeRequest("GET", fmt.Sprintf("/entry/%d", idx)+factory.Format(), nil, nil)
	if err != nil {
		return nil, err
	}
	rv, err := factory.CreateFromBytes(contents)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

// Entries batches requests to fetch entries from the server and returns a channel with the data
// for each entry. Close the context passed to terminate early if desired. If an error is
// encountered, the channel will be closed early before all items are returned.
//
// factory is normally one of one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
func (self *verifiableLogImpl) Entries(ctx context.Context, start, end int64, factory VerifiableEntryFactory) <-chan VerifiableEntry {
	rv := make(chan VerifiableEntry)
	go func() {
		defer close(rv)
		batchSize := int64(500)
		for start < end {
			lastToFetch := start + batchSize
			if lastToFetch > end {
				lastToFetch = end
			}

			contents, _, err := self.Client.MakeRequest("GET", fmt.Sprintf("/entries/%d-%d%s", start, lastToFetch, factory.Format()), nil, nil)
			if err != nil {
				return
			}

			var ger JSONGetEntriesResponse
			err = json.Unmarshal(contents, &ger)
			if err != nil {
				return
			}

			gotOne := false
			for _, e := range ger.Entries {
				if e.Number == start { // good!
					ve, err := factory.CreateFromBytes(e.Data)
					if err != nil {
						return
					}
					select {
					case <-ctx.Done():
						return
					case rv <- ve:
						start++
						gotOne = true
					}
				} else {
					return
				}
			}
			// if we didn't get anything new e.g. wrong type of data factory is a common culprit
			if !gotOne {
				return
			}
		}
	}()
	return rv
}
