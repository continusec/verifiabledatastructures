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

/*
Package verifiabledatastructures provides append-only, verifiable logs and maps. Both a client, server and
embedded options are provided, along with various data storage methods.

This is an early release of the open-source offering, and APIs are subject to change.
If you are using this library, please drop us a note at support@continusec.com so that we
can work with you on any API changes.

To interact with logs and maps, you will first need to get a reference to the low-level
API which is the set of functions defined in pb.VerifiableDataStructuresServiceServer.

Running as embedded instance

Run your own embedded instance:

	// Create an in-memory, non-persistent database, suitable for tests
	db := &TransientHashMapStorage{}

	// Create a service object with no permission checking, and synchronous mutations
	service := (&LocalService{
		AccessPolicy: &AnythingGoesOracle{},
		Mutator:      &InstantMutator{Writer: db},
		Reader:       db,
	}).MustCreate()

Connecting to a server

Connect to a remote server (example below uses GRPCClient, see also HTTPRestClient):

	// Connect to remote GRPC server
	service := (&GRPCClient{
		Address: "verifiabledatastructures.example.com:8081",
	}).MustDial()

Running your own server

To run your own server, simply take a pb.VerifiableDataStructuresServiceServer as created
by LocalService above, and expose like follows:

	StartGRPCServer(&pb.ServerConfig{
		InsecureServerForTesting: true,
		GrpcListenBind:           ":8081",
		GrpcListenProtocol:       "tcp4",
	}, service)

Using the service

Once you have a service object, whether it is local or remote, we recommend that you wrap
it using the higher level Client object:

	client := &Client{
		Service: service,
	}

Note that currently accounts, logs and maps are all created lazily, there is no need to
explicitly create these.

To add entries into a log (ctx can be any valid context, e.g. context.TODO() if unsure):

	promise, err := client.Account("0", "").VerifiableLog().Add(ctx, &pb.LeafData{
		LeafInput: []byte("foo"),
	})

See the documentation for VerifiableLog and VerifiableMap for all operations.

Other storage mechanisms

BoltBackedService:

	// Save logs and maps to data directory using embedded boltdb database
	db := &BoltBackedService{
		Path: "/path/to/database/dir","
	}
	defer db.Close() // Releases file locks

	// pass to LocalService in the same manner as above, e.g.
	service := (&LocalService{
		AccessPolicy: &AnythingGoesOracle{},
		Mutator:      &InstantMutator{Writer: db},
		Reader:       db,
	}).MustCreate()

Other mutation mechanisms

BatchMutator:

	// performs mutations asynchronously in batches - experimental
	service := (&LocalService{
		AccessPolicy: &AnythingGoesOracle{},
		Mutator: (&BatchMutator{
			Writer:     db,
			BatchSize:  1000,
			BufferSize: 100000,
			Timeout:    time.Millisecond * 10,
		}).MustCreate(),
		Reader:       db,
	}).MustCreate()

Other authorization policies

StaticOracle:

	// actually does permission checks, based on static config, e.g.
	service := (&LocalService{
		Mutator:      &InstantMutator{Writer: db},
		Reader:       db,
		AccessPolicy: &StaticOracle{
			Policy: []*pb.ResourceAccount{
				{
					Id: "0",
					Policy: []*pb.AccessPolicy{
						{
							NameMatch:     "foo",
							Permissions:   []pb.Permission{pb.Permission_PERM_ALL_PERMISSIONS},
							ApiKey:        "secret",
							AllowedFields: []string{"*"},
						},
						{
							NameMatch:     "f*",
							Permissions:   []pb.Permission{pb.Permission_PERM_LOG_READ_ENTRY},
							ApiKey:        "*",
							AllowedFields: []string{"name"},
						},
					},
				},
			},
		},
	}).MustCreate()

Each of the above is interchangeable with others that implement the correct interface.

Examples

Here is a full example of using verifiabledatastructures as an embedded storage layer in your application:

	package main

	import (
		"context"
		"log"

		"github.com/continusec/verifiabledatastructures"
		"github.com/continusec/verifiabledatastructures/pb"
		"github.com/golang/protobuf/proto"
	)

	func main() {
		// Create a pointer to a data storage layer, here we persist to disk using Bolt
		db := &verifiabledatastructures.BoltBackedService{
			Path: "/path/to/directory/to/store/data",
		}
		defer db.Close() // Releases file locks

		// Create an instance of the service
		service := (&verifiabledatastructures.LocalService{
			// Allow access to everything
			AccessPolicy: &verifiabledatastructures.AnythingGoesOracle{},

			// Read data from our database
			Reader: db,

			// Apply mutations synchronously
			Mutator: &verifiabledatastructures.InstantMutator{
				Writer: db,
			},
		}).MustCreate()

		// Create a client to directly call the service, no need to stand up a server
		client := &verifiabledatastructures.Client{
			Service: service,
		}

		// Get a pointer to a log
		vlog := client.Account("0", "").VerifiableLog("foo")

		// Create a context (not currently used)
		ctx := context.Background()

		// Add something to it
		_, err := vlog.Add(ctx, &pb.LeafData{
			LeafInput: []byte("bar"),
		})
		if err != nil {
			log.Fatal(err)
		}

		// Print tree head
		th, err := vlog.TreeHead(ctx, verifiabledatastructures.Head)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(proto.CompactTextString(th))
	}

*/
package verifiabledatastructures

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

// VerifiableMap is an object used to interace with Verifiable Maps.
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
func (g *VerifiableLog) TreeHead(ctx context.Context, treeSize int64) (*pb.LogTreeHashResponse, error) {
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
func (g *VerifiableLog) Add(ctx context.Context, e *pb.LeafData) (LogUpdatePromise, error) {
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
func (g *VerifiableLog) InclusionProof(ctx context.Context, treeSize int64, leaf []byte) (*pb.LogInclusionProofResponse, error) {
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
func (g *VerifiableLog) InclusionProofByIndex(ctx context.Context, treeSize, leafIndex int64) (*pb.LogInclusionProofResponse, error) {
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
func (g *VerifiableLog) ConsistencyProof(ctx context.Context, first, second int64) (*pb.LogConsistencyProofResponse, error) {
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
func (g *VerifiableLog) Entry(ctx context.Context, idx int64) (*pb.LeafData, error) {
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
func (g *VerifiableLog) Entries(ctx context.Context, start, end int64) <-chan *pb.LeafData {
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
func (g *VerifiableMap) Get(ctx context.Context, key []byte, treeSize int64) (*pb.MapGetValueResponse, error) {
	return g.Service.MapGetValue(ctx, &pb.MapGetValueRequest{
		Key:      key,
		Map:      g.Map,
		TreeSize: treeSize,
	})
}

// Set will generate a map mutation to set the given value for the given key.
// While this will return quickly, the change will be reflected asynchronously in the map.
// Returns an AddEntryResponse which contains the leaf hash for the mutation log entry.
func (g *VerifiableMap) Set(ctx context.Context, key []byte, value *pb.LeafData) (MapUpdatePromise, error) {
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
func (g *VerifiableMap) Delete(ctx context.Context, key []byte) (MapUpdatePromise, error) {
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
func (g *VerifiableMap) Update(ctx context.Context, key []byte, value *pb.LeafData, previousLeaf []byte) (MapUpdatePromise, error) {
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
func (g *VerifiableMap) TreeHead(ctx context.Context, treeSize int64) (*pb.MapTreeHashResponse, error) {
	return g.Service.MapTreeHash(ctx, &pb.MapTreeHashRequest{
		Map:      g.Map,
		TreeSize: treeSize,
	})
}

type mapSetPromise struct {
	Map *VerifiableMap
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
	Log *VerifiableLog
	MTL []byte
}

func (p *logAddPromise) LeafHash() []byte {
	return p.MTL
}

func (p *logAddPromise) Wait(ctx context.Context) (*pb.LogTreeHashResponse, error) {
	return p.Log.BlockUntilPresent(ctx, p.MTL)
}
