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
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/continusec/verifiabledatastructures/api"
	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/kvstore"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/server"
	"golang.org/x/net/context"
)

type Failable interface {
	Error(args ...interface{})
}

type DummyTester struct {
	failed bool
}

func (f *DummyTester) Error(args ...interface{}) {
	fmt.Println(args...)
	fmt.Println("FAILURE!!!")
	f.failed = true
	panic("aaeerrgghh!!")
}

func testMap(t *testing.T, baseURL string) {
	account := client.DefaultClient.WithBaseUrl(baseURL+"/v1").Account("999", "secret")
	vmap := account.VerifiableMap("testmap")
	numToDo := 10

	for i := 0; i < numToDo; i++ {
		_, err := vmap.Set([]byte(fmt.Sprintf("foo%d", i)), &client.RawDataEntry{RawBytes: []byte(fmt.Sprintf("fooval%d", i))})
		if err != nil {
			t.Fatal(err)
		}
	}

	_, err := client.MapBlockUntilSize(vmap, int64(numToDo))
	if err != nil {
		t.Fatal(err)
	}

	ms, err := client.MapVerifiedLatestMapState(vmap, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < numToDo; i++ {
		entry, err := client.MapVerifiedGet(vmap, []byte(fmt.Sprintf("foo%d", i)), ms, client.RawDataEntryFactory)
		if err != nil {
			t.Fatal(err)
		}
		dd, err := entry.Data()
		if err != nil {
			t.Fatal(err)
		}
		if string(dd) != fmt.Sprintf("fooval%d", i) {
			t.Fatal(string(dd))
		}
	}
}

func testLog(t *testing.T, baseURL string) {
	account := client.DefaultClient.WithBaseUrl(baseURL+"/v1").Account("999", "secret")
	log := account.VerifiableLog("smoketest")

	treeRoot, err := log.TreeHead(client.Head)
	if !(treeRoot == nil || (treeRoot.TreeSize == 0 && len(treeRoot.RootHash) == 0)) {
		t.Fatal("Expecting log to not exist.")
	}

	aer, err := log.Add(&client.RawDataEntry{RawBytes: []byte("foo")})
	if err != nil {
		t.Fatal("Failed adding item", err)
	}

	lh, err := aer.LeafHash()
	if err != nil {
		t.Fatal("Failed adding item")
	}
	if !bytes.Equal(lh, client.LeafMerkleTreeHash([]byte("foo"))) {
		t.Fatal("Failed adding item")
	}

	for treeRoot == nil || treeRoot.TreeSize < 1 {
		treeRoot, err = log.TreeHead(client.Head)
		if err != nil {
			t.Fatal("Failure getting root hash")
		}
	}

	if !bytes.Equal(treeRoot.RootHash, client.LeafMerkleTreeHash([]byte("foo"))) {
		t.Fatal("Failed calculating tree root")
	}

	_, err = log.Add(&client.RawDataEntry{RawBytes: []byte("fooz")})
	if err != nil {
		t.Fatal("Failed adding item")
	}

	_, err = log.Add(&client.RawDataEntry{RawBytes: []byte("bar")})
	if err != nil {
		t.Fatal("Failed adding item")
	}

	_, err = log.Add(&client.RawDataEntry{RawBytes: []byte("baz")})
	if err != nil {
		t.Fatal("Failed adding item")
	}

	_, err = log.Add(&client.RawDataEntry{RawBytes: []byte("smez")})
	if err != nil {
		t.Fatal("Failed adding item")
	}

	for treeRoot.TreeSize != 5 {
		treeRoot, err = log.TreeHead(0)
		if err != nil {
			t.Fatal("Failure getting root hash")
		}
	}

	entries := make([]client.VerifiableEntry, treeRoot.TreeSize)
	for i := int64(0); i < treeRoot.TreeSize; i++ {
		entries[i], err = log.Entry(i, client.RawDataEntryFactory)
		if err != nil {
			t.Fatal("Failure getting entry")
		}
	}

	if !verifyRootHash(entries, treeRoot.RootHash) {
		t.Fatal("Failure verifying root hash")
	}

	for i := 0; i < 200; i++ {
		_, err := log.Add(&client.RawDataEntry{RawBytes: []byte(fmt.Sprintf("foo %d", rand.Int()))})
		if err != nil {
			t.Fatal("Failed adding item")
		}
	}

	for treeRoot.TreeSize != 205 {
		treeRoot, err = log.TreeHead(client.Head)
		if err != nil {
			t.Fatal("Failure getting root hash")
		}
	}

	th3, err := log.TreeHead(3)
	if err != nil {
		t.Fatal("Failure getting root hash")
	}

	th7, err := log.TreeHead(7)
	if err != nil {
		t.Fatal("Failure getting root hash")
	}

	err = client.LogVerifyConsistency(log, th3, th7)
	if err != nil {
		t.Fatal("Failure to generate consistency between 3 and 7")
	}

	rootHashes := generateRootHashes(context.Background(), log.Entries(context.Background(), 0, treeRoot.TreeSize, client.RawDataEntryFactory))
	i := 0
	var last []byte
	for rh := range rootHashes {
		last = rh
		i++
	}
	if i != 205 {
		t.Fatal("Wrong i")
	}
	if !bytes.Equal(treeRoot.RootHash, last) {
		t.Fatal("Failed calculating tree root")
	}

	for i := 0; i < 200; i++ {
		_, err := log.Add(&client.RawDataEntry{RawBytes: []byte(fmt.Sprintf("foo %d", rand.Int()))})
		if err != nil {
			t.Fatal("Failed adding item")
		}
	}

	for treeRoot.TreeSize != 405 {
		treeRoot, err = log.TreeHead(client.Head)
		if err != nil {
			t.Fatal("Failure getting root hash")
		}
	}

	rootHashes = generateRootHashes(context.Background(), log.Entries(context.Background(), 0, treeRoot.TreeSize, client.RawDataEntryFactory))
	i = 0
	for rh := range rootHashes {
		last = rh
		i++
	}
	if i != 405 {
		t.Fatal("Wrong i")
	}
	if !bytes.Equal(treeRoot.RootHash, last) {
		t.Fatal("Failed calculating tree root")
	}
}

func TestFullIntegration(t *testing.T) {
	db := &kvstore.TransientHashMapStorage{}
	service := &api.LocalService{
		AccessPolicy: &api.StaticOracle{},
		Mutator: &api.InstantMutator{
			Writer: db,
		},
		Reader: db,
	}

	go server.StartRESTServer(&pb.ServerConfig{
		InsecureServerForTesting: true,
		RestListenBind:           ":8092",
		RestServer:               true,
	}, service)
	time.Sleep(time.Millisecond * 50) // let the server startup...

	testMap(t, "http://localhost:8092")
	testLog(t, "http://localhost:8092")
}

// GenerateRootHashes is a utility function that emits a channel of root hashes
// given a channel of input values. This is useful for some unit tests.
func generateRootHashes(ctx context.Context, input <-chan client.VerifiableEntry) <-chan []byte {
	rv := make(chan []byte)
	go func() {
		defer close(rv)
		index := 0
		stack := make([][]byte, 0)
		for {
			select {
			case <-ctx.Done():
				return
			case b, ok := <-input:
				if !ok {
					return
				}
				d, err := b.Data()
				if err != nil {
					return
				}
				stack = append(stack, client.LeafMerkleTreeHash(d))
			}

			for j := index; (j & 1) == 1; j >>= 1 {
				stack = append(stack[:len(stack)-2], client.NodeMerkleTreeHash(stack[len(stack)-2], stack[len(stack)-1]))
			}

			rh := stack[len(stack)-1]
			for j := len(stack) - 2; j >= 0; j-- {
				rh = client.NodeMerkleTreeHash(stack[j], rh)
			}

			select {
			case <-ctx.Done():
				return
			case rv <- rh:
				index++
			}
		}
	}()
	return rv
}

func verifyRootHash(entries []client.VerifiableEntry, answer []byte) bool {
	stack := make([][]byte, 0)
	for i, b := range entries {
		d, err := b.Data()
		if err != nil {
			return false
		}
		stack = append(stack, client.LeafMerkleTreeHash(d))
		for j := i; (j & 1) == 1; j >>= 1 {
			stack = append(stack[:len(stack)-2], client.NodeMerkleTreeHash(stack[len(stack)-2], stack[len(stack)-1]))
		}
	}
	for len(stack) > 1 {
		stack = append(stack[:len(stack)-2], client.NodeMerkleTreeHash(stack[len(stack)-2], stack[len(stack)-1]))
	}
	return bytes.Equal(stack[0], answer)
}
