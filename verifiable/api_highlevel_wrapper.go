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

package verifiable

import (
	"github.com/continusec/verifiabledatastructures/pb"
	"golang.org/x/net/context"
)

// Client is the primary point to begin interaction with
// a verifiable data structures service. This client providers convenience wrappers around
// an underlying lower-level API.
type Client struct {
	Service pb.VerifiableDataStructuresServiceServer
}

// Account returns an object that can be used to access objects within that account
func (v *Client) Account(id string, apiKey string) *Account {
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
func (acc *Account) VerifiableMap(name string) *Map {
	return &Map{
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
func (acc *Account) VerifiableLog(name string) *Log {
	return &Log{
		Log: &pb.LogRef{
			Account: acc.Account,
			Name:    name,
			LogType: pb.LogType_STRUCT_TYPE_LOG,
		},
		Service: acc.Service,
	}
}

// Map is an object used to interace with Verifiable Maps.
type Map struct {
	Map     *pb.MapRef
	Service pb.VerifiableDataStructuresServiceServer
}

// Log is an object used to interact with Verifiable Logs. To construct this
// object, call NewClient(...).VerifiableLog("logname")
type Log struct {
	Log     *pb.LogRef
	Service pb.VerifiableDataStructuresServiceServer
}

// TreeHead returns tree root hash for the log at the given tree size. Specify continusec.Head
// to receive a root hash for the latest tree size.
func (g *Log) TreeHead(ctx context.Context, treeSize int64) (*pb.LogTreeHashResponse, error) {
	return g.Service.LogTreeHash(ctx, &pb.LogTreeHashRequest{
		Log:      g.Log,
		TreeSize: treeSize,
	})
}

// Add will send an API call to add the specified entry to the log. If the exact entry
// already exists in the log, it will not be added a second time.
// Returns an AddEntryResponse which includes the leaf hash, whether it is a duplicate or not. Note that the
// entry is sequenced in the underlying log in an asynchronous fashion, so the tree size
// will not immediately increase, and inclusion proof checks will not reflect the new entry
// until it is sequenced.
func (g *Log) Add(ctx context.Context, e *pb.LeafData) (LogUpdatePromise, error) {
	resp, err := g.Service.LogAddEntry(ctx, &pb.LogAddEntryRequest{
		Log:   g.Log,
		Value: e,
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
func (g *Log) InclusionProof(ctx context.Context, treeSize int64, leaf []byte) (*pb.LogInclusionProofResponse, error) {
	return g.Service.LogInclusionProof(ctx, &pb.LogInclusionProofRequest{
		Log:      g.Log,
		MtlHash:  leaf,
		TreeSize: treeSize,
	})
}

// InclusionProofByIndex will return an inclusion proof for a specified tree size and leaf index.
// This is not used by typical clients, however it can be useful for certain audit operations and debugging tools.
// The LogInclusionProof returned by this method will not have the LeafHash filled in and as such will fail to verify.
//
// Typical clients will instead use VerifyInclusionProof().
func (g *Log) InclusionProofByIndex(ctx context.Context, treeSize, leafIndex int64) (*pb.LogInclusionProofResponse, error) {
	return g.Service.LogInclusionProof(ctx, &pb.LogInclusionProofRequest{
		Log:       g.Log,
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
	})
}

// ConsistencyProof returns an audit path which contains the set of Merkle Subtree hashes
// that demonstrate how the root hash is calculated for both the first and second tree sizes.
//
// Most clients instead use VerifyInclusionProof which additionally verifies the returned proof.
func (g *Log) ConsistencyProof(ctx context.Context, first, second int64) (*pb.LogConsistencyProofResponse, error) {
	return g.Service.LogConsistencyProof(ctx, &pb.LogConsistencyProofRequest{
		Log:      g.Log,
		FromSize: first,
		TreeSize: second,
	})
}

// Entry returns the entry stored for the given index using the passed in factory to instantiate the entry.
// This is normally one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
// If the entry was stored using one of the ObjectHash formats, then the data returned by a RawDataEntryFactory,
// then the object hash itself is returned as the contents. To get the data itself, use JsonEntryFactory.
func (g *Log) Entry(ctx context.Context, idx int64) (*pb.LeafData, error) {
	resp, err := g.Service.LogFetchEntries(ctx, &pb.LogFetchEntriesRequest{
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
func (g *Log) Entries(ctx context.Context, start, end int64) <-chan *pb.LeafData {
	rv := make(chan *pb.LeafData)
	go func() {
		defer close(rv)
		batchSize := int64(500)
		for start < end {
			lastToFetch := start + batchSize
			if lastToFetch > end {
				lastToFetch = end
			}

			resp, err := g.Service.LogFetchEntries(ctx, &pb.LogFetchEntriesRequest{
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
func (g *Map) MutationLog() *Log {
	return &Log{
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
func (g *Map) TreeHeadLog() *Log {
	return &Log{
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
func (g *Map) Get(ctx context.Context, key []byte, treeSize int64) (*pb.MapGetValueResponse, error) {
	return g.Service.MapGetValue(ctx, &pb.MapGetValueRequest{
		Key:      key,
		Map:      g.Map,
		TreeSize: treeSize,
	})
}

// Set will generate a map mutation to set the given value for the given key.
// While this will return quickly, the change will be reflected asynchronously in the map.
// Returns an AddEntryResponse which contains the leaf hash for the mutation log entry.
func (g *Map) Set(ctx context.Context, key []byte, value *pb.LeafData) (MapUpdatePromise, error) {
	resp, err := g.Service.MapSetValue(ctx, &pb.MapSetValueRequest{
		Map: g.Map,
		Mutation: &pb.MapMutation{
			Action: "set",
			Key:    key,
			Value:  value,
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
func (g *Map) Delete(ctx context.Context, key []byte) (MapUpdatePromise, error) {
	resp, err := g.Service.MapSetValue(ctx, &pb.MapSetValueRequest{
		Map: g.Map,
		Mutation: &pb.MapMutation{
			Action: "delete",
			Key:    key,
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

// Update will generate a map mutation to set the given value for the given key, conditional on the
// previous leaf hash being that specified by previousLeaf.
// While this will return quickly, the change will be reflected asynchronously in the map.
// Returns an AddEntryResponse which contains the leaf hash for the mutation log entry.
func (g *Map) Update(ctx context.Context, key []byte, value *pb.LeafData, previousLeaf []byte) (MapUpdatePromise, error) {
	resp, err := g.Service.MapSetValue(ctx, &pb.MapSetValueRequest{
		Map: g.Map,
		Mutation: &pb.MapMutation{
			Action:           "update",
			Key:              key,
			Value:            value,
			PreviousLeafHash: previousLeaf,
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

// TreeHead returns map root hash for the map at the given tree size. Specify continusec.Head
// to receive a root hash for the latest tree size.
func (g *Map) TreeHead(ctx context.Context, treeSize int64) (*pb.MapTreeHashResponse, error) {
	return g.Service.MapTreeHash(ctx, &pb.MapTreeHashRequest{
		Map:      g.Map,
		TreeSize: treeSize,
	})
}

type mapSetPromise struct {
	Map *Map
	MTL []byte
}

func (p *mapSetPromise) LeafHash() []byte {
	return p.MTL
}

func (p *mapSetPromise) Wait(ctx context.Context) (*pb.MapTreeHashResponse, error) {
	lth, err := p.Map.MutationLog().BlockUntilPresent(ctx, p.MTL)
	if err != nil {
		return nil, err
	}
	return p.Map.TreeHead(ctx, lth.TreeSize)
}

type logAddPromise struct {
	Log *Log
	MTL []byte
}

func (p *logAddPromise) LeafHash() []byte {
	return p.MTL
}

func (p *logAddPromise) Wait(ctx context.Context) (*pb.LogTreeHashResponse, error) {
	return p.Log.BlockUntilPresent(ctx, p.MTL)
}
