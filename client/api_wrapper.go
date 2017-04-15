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
	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/pb"
)

// VerifiableDataStructuresClient
type VerifiableDataStructuresClient struct {
	Service pb.VerifiableDataStructuresServiceServer
}

// Account returns an object that can be used to access objects within that account
func (v *VerifiableDataStructuresClient) Account(id string, apiKey string) *Account {
	return &Account{
		Account: &pb.AccountRef{
			Id:     id,
			ApiKey: apiKey,
		},
		Service: v.Service,
	}
}

// Account is used to access your Continusec account.
type Account struct {
	Account *pb.AccountRef
	APIKey  string
	Service pb.VerifiableDataStructuresServiceServer
}

// VerifiableMap returns an object representing a Verifiable Map. This function simply
// returns a pointer to an object that can be used to interact with the Map, and won't
// by itself cause any API calls to be generated.
func (acc *Account) VerifiableMap(name string) *VerifiableMap {
	return &VerifiableMap{
		Map: &pb.MapRef{
			Account: acc.Account,
			Name:    name,
		},
		Service: acc.Service,
	}
}

// VerifiableLog returns an object representing a Verifiable Log. This function simply
// returns a pointer to an object that can be used to interact with the Log, and won't
// by itself cause any API calls to be generated.
func (acc *Account) VerifiableLog(name string) *VerifiableLog {
	return &VerifiableLog{
		Log: &pb.LogRef{
			Account: acc.Account,
			Name:    name,
			LogType: pb.LogType_STRUCT_TYPE_LOG,
		},
		Service: acc.Service,
	}
}

type VerifiableMap struct {
	Map     *pb.MapRef
	Service pb.VerifiableDataStructuresServiceServer
}

// VerifiableLog is an object used to interact with Verifiable Logs. To construct this
// object, call NewClient(...).VerifiableLog("logname")
type VerifiableLog struct {
	Log     *pb.LogRef
	Service pb.VerifiableDataStructuresServiceServer
}

// TreeHead returns tree root hash for the log at the given tree size. Specify continusec.Head
// to receive a root hash for the latest tree size.
func (g *VerifiableLog) TreeHead(treeSize int64) (*LogTreeHead, error) {
	resp, err := g.Service.LogTreeHash(context.Background(), &pb.LogTreeHashRequest{
		Log:      g.Log,
		TreeSize: treeSize,
	})
	if err != nil {
		return nil, err
	}
	return &LogTreeHead{
		RootHash: resp.RootHash,
		TreeSize: resp.TreeSize,
	}, nil
}

// Add will send an API call to add the specified entry to the log. If the exact entry
// already exists in the log, it will not be added a second time.
// Returns an AddEntryResponse which includes the leaf hash, whether it is a duplicate or not. Note that the
// entry is sequenced in the underlying log in an asynchronous fashion, so the tree size
// will not immediately increase, and inclusion proof checks will not reflect the new entry
// until it is sequenced.
func (g *VerifiableLog) Add(e VerifiableData) (LogUpdatePromise, error) {
	resp, err := g.Service.LogAddEntry(context.Background(), &pb.LogAddEntryRequest{
		Log: g.Log,
		Data: &pb.LeafData{
			LeafInput: e.GetLeafInput(),
			ExtraData: e.GetExtraData(),
		},
	})
	if err != nil {
		return nil, err
	}
	return &logAddPromise{
		Log: g,
		MTL: resp.LeafHash,
	}, nil
}

// InclusionProof will return a proof the the specified MerkleTreeLeaf is included in the
// log. The proof consists of the index within the log that the entry is stored, and an
// audit path which returns the corresponding leaf nodes that can be applied to the input
// leaf hash to generate the root tree hash for the log.
//
// Most clients instead use VerifyInclusion which additionally verifies the returned proof.
func (g *VerifiableLog) InclusionProof(treeSize int64, leaf MerkleTreeLeaf) (*LogInclusionProof, error) {
	h, err := leaf.LeafHash()
	if err != nil {
		return nil, err
	}
	resp, err := g.Service.LogInclusionProof(context.Background(), &pb.LogInclusionProofRequest{
		Log:      g.Log,
		MtlHash:  h,
		TreeSize: treeSize,
	})
	if err != nil {
		return nil, err
	}
	return &LogInclusionProof{
		AuditPath: resp.AuditPath,
		LeafHash:  h,
		LeafIndex: resp.LeafIndex,
		TreeSize:  resp.TreeSize,
	}, nil
}

// InclusionProofByIndex will return an inclusion proof for a specified tree size and leaf index.
// This is not used by typical clients, however it can be useful for certain audit operations and debugging tools.
// The LogInclusionProof returned by this method will not have the LeafHash filled in and as such will fail to verify.
//
// Typical clients will instead use VerifyInclusionProof().
func (g *VerifiableLog) InclusionProofByIndex(treeSize, leafIndex int64) (*LogInclusionProof, error) {
	resp, err := g.Service.LogInclusionProof(context.Background(), &pb.LogInclusionProofRequest{
		Log:       g.Log,
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
	})
	if err != nil {
		return nil, err
	}
	return &LogInclusionProof{
		AuditPath: resp.AuditPath,
		LeafIndex: resp.LeafIndex,
		TreeSize:  resp.TreeSize,
	}, nil
}

// ConsistencyProof returns an audit path which contains the set of Merkle Subtree hashes
// that demonstrate how the root hash is calculated for both the first and second tree sizes.
//
// Most clients instead use VerifyInclusionProof which additionally verifies the returned proof.
func (g *VerifiableLog) ConsistencyProof(first, second int64) (*LogConsistencyProof, error) {
	resp, err := g.Service.LogConsistencyProof(context.Background(), &pb.LogConsistencyProofRequest{
		Log:      g.Log,
		FromSize: first,
		TreeSize: second,
	})
	if err != nil {
		return nil, err
	}
	return &LogConsistencyProof{
		AuditPath:  resp.AuditPath,
		FirstSize:  resp.FromSize,
		SecondSize: resp.TreeSize,
	}, nil
}

// Entry returns the entry stored for the given index using the passed in factory to instantiate the entry.
// This is normally one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
// If the entry was stored using one of the ObjectHash formats, then the data returned by a RawDataEntryFactory,
// then the object hash itself is returned as the contents. To get the data itself, use JsonEntryFactory.
func (g *VerifiableLog) Entry(idx int64) (VerifiableData, error) {
	resp, err := g.Service.LogFetchEntries(context.Background(), &pb.LogFetchEntriesRequest{
		Log:   g.Log,
		First: idx,
		Last:  idx + 1,
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Values) != 1 {
		return nil, ErrNotFound
	}
	return resp.Values[0], nil
}

// Entries batches requests to fetch entries from the server and returns a channel with the data
// for each entry. Close the context passed to terminate early if desired. If an error is
// encountered, the channel will be closed early before all items are returned.
//
// factory is normally one of one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
func (g *VerifiableLog) Entries(ctx context.Context, start, end int64) <-chan VerifiableData {
	rv := make(chan VerifiableData)
	go func() {
		defer close(rv)
		batchSize := int64(500)
		for start < end {
			lastToFetch := start + batchSize
			if lastToFetch > end {
				lastToFetch = end
			}

			resp, err := g.Service.LogFetchEntries(context.Background(), &pb.LogFetchEntriesRequest{
				Log:   g.Log,
				First: start,
				Last:  lastToFetch,
			})
			if err != nil {
				return
			}

			gotOne := false
			for _, e := range resp.Values {
				select {
				case <-ctx.Done():
					return
				case rv <- e:
					start++
					gotOne = true
				}

			}
			// if we didn't get anything new
			if !gotOne {
				return
			}
		}
	}()
	return rv
}

// MutationLog returns a pointer to the underlying Verifiable Log that represents
// a log of mutations to this map. Since this Verifiable Log is managed by this map,
// the log returned cannot be directly added to (to mutate, call Set and Delete methods
// on the map), however all read-only functions are present.
func (g *VerifiableMap) MutationLog() *VerifiableLog {
	return &VerifiableLog{
		Service: g.Service,
		Log: &pb.LogRef{
			Account: g.Map.Account,
			Name:    g.Map.Name,
			LogType: pb.LogType_STRUCT_TYPE_MUTATION_LOG,
		},
	}
}

// TreeHeadLog returns a pointer to the underlying Verifiable Log that represents
// a log of tree heads generated by this map. Since this Verifiable Map is managed by this map,
// the log returned cannot be directly added to however all read-only functions are present.
func (g *VerifiableMap) TreeHeadLog() *VerifiableLog {
	return &VerifiableLog{
		Service: g.Service,
		Log: &pb.LogRef{
			Account: g.Map.Account,
			Name:    g.Map.Name,
			LogType: pb.LogType_STRUCT_TYPE_TREEHEAD_LOG,
		},
	}
}

// Get will return the value for the given key at the given treeSize. Pass continusec.Head
// to always get the latest value. factory is normally one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
//
// Clients normally instead call VerifiedGet() with a MapTreeHead returned by VerifiedLatestMapState as this will also perform verification of inclusion.
func (g *VerifiableMap) Get(key []byte, treeSize int64) (*MapInclusionProof, error) {
	resp, err := g.Service.MapGetValue(context.Background(), &pb.MapGetValueRequest{
		Key:      key,
		Map:      g.Map,
		TreeSize: treeSize,
	})
	if err != nil {
		return nil, err
	}
	return &MapInclusionProof{
		AuditPath: resp.AuditPath,
		Key:       key,
		TreeSize:  resp.TreeSize,
		Value:     resp.Value,
	}, nil
}

// Set will generate a map mutation to set the given value for the given key.
// While this will return quickly, the change will be reflected asynchronously in the map.
// Returns an AddEntryResponse which contains the leaf hash for the mutation log entry.
func (g *VerifiableMap) Set(key []byte, value VerifiableData) (MapUpdatePromise, error) {
	resp, err := g.Service.MapSetValue(context.Background(), &pb.MapSetValueRequest{
		Key:    key,
		Map:    g.Map,
		Action: pb.MapMutationAction_MAP_MUTATION_SET,
		Value: &pb.LeafData{
			LeafInput: value.GetLeafInput(),
			ExtraData: value.GetExtraData(),
		},
	})
	if err != nil {
		return nil, err
	}
	return &mapSetPromise{
		Map: g,
		MTL: resp.LeafHash,
	}, nil
}

// Delete will set generate a map mutation to delete the value for the given key. Calling Delete
// is equivalent to calling Set with an empty value.
// While this will return quickly, the change will be reflected asynchronously in the map.
// Returns an AddEntryResponse which contains the leaf hash for the mutation log entry.
func (g *VerifiableMap) Delete(key []byte) (MapUpdatePromise, error) {
	resp, err := g.Service.MapSetValue(context.Background(), &pb.MapSetValueRequest{
		Key:    key,
		Map:    g.Map,
		Action: pb.MapMutationAction_MAP_MUTATION_DELETE,
	})
	if err != nil {
		return nil, err
	}
	return &mapSetPromise{
		Map: g,
		MTL: resp.LeafHash,
	}, nil
}

// Update will generate a map mutation to set the given value for the given key, conditional on the
// previous leaf hash being that specified by previousLeaf.
// While this will return quickly, the change will be reflected asynchronously in the map.
// Returns an AddEntryResponse which contains the leaf hash for the mutation log entry.
func (g *VerifiableMap) Update(key []byte, value VerifiableData, previousLeaf MerkleTreeLeaf) (MapUpdatePromise, error) {
	prev, err := previousLeaf.LeafHash()
	if err != nil {
		return nil, err
	}
	resp, err := g.Service.MapSetValue(context.Background(), &pb.MapSetValueRequest{
		Key:    key,
		Map:    g.Map,
		Action: pb.MapMutationAction_MAP_MUTATION_UPDATE,
		Value: &pb.LeafData{
			LeafInput: value.GetLeafInput(),
			ExtraData: value.GetExtraData(),
		},
		PrevLeafHash: prev,
	})
	if err != nil {
		return nil, err
	}
	return &mapSetPromise{
		Map: g,
		MTL: resp.LeafHash,
	}, nil
}

// TreeHead returns map root hash for the map at the given tree size. Specify continusec.Head
// to receive a root hash for the latest tree size.
func (g *VerifiableMap) TreeHead(treeSize int64) (*MapTreeHead, error) {
	resp, err := g.Service.MapTreeHash(context.Background(), &pb.MapTreeHashRequest{
		Map:      g.Map,
		TreeSize: treeSize,
	})
	if err != nil {
		return nil, err
	}
	return &MapTreeHead{
		RootHash: resp.RootHash,
		MutationLogTreeHead: LogTreeHead{
			RootHash: resp.MutationLog.RootHash,
			TreeSize: resp.MutationLog.TreeSize,
		},
	}, nil
}

type mapSetPromise struct {
	Map *VerifiableMap
	MTL []byte
}

func (p *mapSetPromise) LeafHash() ([]byte, error) {
	return p.MTL, nil
}

func (p *mapSetPromise) Wait() (*MapTreeHead, error) {
	return nil, ErrObjectConflict
}

type logAddPromise struct {
	Log *VerifiableLog
	MTL []byte
}

func (p *logAddPromise) LeafHash() ([]byte, error) {
	return p.MTL, nil
}

func (p *logAddPromise) Wait() (*LogTreeHead, error) {
	return nil, ErrObjectConflict
}
