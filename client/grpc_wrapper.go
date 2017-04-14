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

type VerifiableDataStructuresClient struct {
	Service pb.VerifiableDataStructuresServiceServer
}

// Account returns an object that can be used to access objects within that account
func (v *VerifiableDataStructuresClient) Account(id string, apiKey string) Account {
	return &gRpcAccountImpl{
		Account: &pb.AccountRef{
			Id:     id,
			ApiKey: apiKey,
		},
		Service: v.Service,
	}
}

type gRpcAccountImpl struct {
	Account *pb.AccountRef
	APIKey  string
	Service pb.VerifiableDataStructuresServiceServer
}

// VerifiableMap returns an object representing a Verifiable Map. This function simply
// returns a pointer to an object that can be used to interact with the Map, and won't
// by itself cause any API calls to be generated.
func (acc *gRpcAccountImpl) VerifiableMap(name string) VerifiableMap {
	return &gRpcVerifiableMapImpl{
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
func (acc *gRpcAccountImpl) VerifiableLog(name string) VerifiableLog {
	return &gRpcVerifiableLogImpl{
		Log: &pb.LogRef{
			Account: acc.Account,
			Name:    name,
			LogType: pb.LogType_STRUCT_TYPE_LOG,
		},
		Service: acc.Service,
	}
}

type gRpcVerifiableMapImpl struct {
	Map     *pb.MapRef
	Service pb.VerifiableDataStructuresServiceServer
}

type gRpcVerifiableLogImpl struct {
	Log     *pb.LogRef
	Service pb.VerifiableDataStructuresServiceServer
}

func (g *gRpcVerifiableLogImpl) TreeHead(treeSize int64) (*LogTreeHead, error) {
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

func (g *gRpcVerifiableLogImpl) Add(e VerifiableData) (LogUpdatePromise, error) {
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
func (g *gRpcVerifiableLogImpl) InclusionProof(treeSize int64, leaf MerkleTreeLeaf) (*LogInclusionProof, error) {
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
func (g *gRpcVerifiableLogImpl) InclusionProofByIndex(treeSize, leafIndex int64) (*LogInclusionProof, error) {
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
func (g *gRpcVerifiableLogImpl) ConsistencyProof(first, second int64) (*LogConsistencyProof, error) {
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
func (g *gRpcVerifiableLogImpl) Entry(idx int64) (VerifiableData, error) {
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
func (g *gRpcVerifiableLogImpl) Entries(ctx context.Context, start, end int64) <-chan VerifiableData {
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

func (g *gRpcVerifiableMapImpl) MutationLog() VerifiableLog {
	return &gRpcVerifiableLogImpl{
		Service: g.Service,
		Log: &pb.LogRef{
			Account: g.Map.Account,
			Name:    g.Map.Name,
			LogType: pb.LogType_STRUCT_TYPE_MUTATION_LOG,
		},
	}
}

func (g *gRpcVerifiableMapImpl) TreeHeadLog() VerifiableLog {
	return &gRpcVerifiableLogImpl{
		Service: g.Service,
		Log: &pb.LogRef{
			Account: g.Map.Account,
			Name:    g.Map.Name,
			LogType: pb.LogType_STRUCT_TYPE_TREEHEAD_LOG,
		},
	}
}

func (g *gRpcVerifiableMapImpl) Get(key []byte, treeSize int64) (*MapInclusionProof, error) {
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

func (g *gRpcVerifiableMapImpl) Set(key []byte, value VerifiableData) (MapUpdatePromise, error) {
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
func (g *gRpcVerifiableMapImpl) Delete(key []byte) (MapUpdatePromise, error) {
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
func (g *gRpcVerifiableMapImpl) Update(key []byte, value VerifiableData, previousLeaf MerkleTreeLeaf) (MapUpdatePromise, error) {
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
func (g *gRpcVerifiableMapImpl) TreeHead(treeSize int64) (*MapTreeHead, error) {
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
	Map VerifiableMap
	MTL []byte
}

func (p *mapSetPromise) LeafHash() ([]byte, error) {
	return p.MTL, nil
}

func (p *mapSetPromise) Wait() (*MapTreeHead, error) {
	return nil, ErrObjectConflict
}

type logAddPromise struct {
	Log VerifiableLog
	MTL []byte
}

func (p *logAddPromise) LeafHash() ([]byte, error) {
	return p.MTL, nil
}

func (p *logAddPromise) Wait() (*LogTreeHead, error) {
	return nil, ErrObjectConflict
}
