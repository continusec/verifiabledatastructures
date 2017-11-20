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
	"log"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/continusec/verifiabledatastructures/pb"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func testMap(ctx context.Context, t *testing.T, service pb.VerifiableDataStructuresServiceServer) {
	account := (&Client{
		Service: service,
	}).Account("999", "secret")
	vmap := account.VerifiableMap("testmap")
	numToDo := 1000

	var lastP MapUpdatePromise
	var err error
	for i := 0; i < numToDo; i++ {
		lastP, err = vmap.Set(ctx, []byte(fmt.Sprintf("foo%d", i)), &pb.LeafData{LeafInput: []byte(fmt.Sprintf("fooval%d", i))})
		if err != nil {
			t.Fatal(err)
		}
	}

	_, err = lastP.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}

	ms, err := vmap.VerifiedLatestMapState(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make sure we don't break on non-existent entries
	for i := 0; i < numToDo; i++ {
		entry, err := vmap.VerifiedGet(ctx, []byte(fmt.Sprintf("baz%d", i)), ms)
		if err != nil {
			t.Fatal(err)
		}
		dd := entry.GetLeafInput()
		if len(dd) != 0 {
			t.Fatal(string(dd))
		}
	}

	for i := 0; i < numToDo; i++ {
		entry, err := vmap.VerifiedGet(ctx, []byte(fmt.Sprintf("foo%d", i)), ms)
		if err != nil {
			t.Fatal(err)
		}
		dd := entry.GetLeafInput()
		if string(dd) != fmt.Sprintf("fooval%d", i) {
			t.Fatal(string(dd))
		}
	}
}

func testLog(ctx context.Context, t *testing.T, service pb.VerifiableDataStructuresServiceServer) {
	account := (&Client{
		Service: service,
	}).Account("999", "secret")
	log := account.VerifiableLog("smoketest")

	treeRoot, err := log.TreeHead(ctx, 0)
	if !(treeRoot == nil || (treeRoot.TreeSize == 0 && len(treeRoot.RootHash) == 0)) {
		t.Fatal("Expecting log to not exist.")
	}

	aer, err := log.Add(ctx, &pb.LeafData{LeafInput: []byte("foo")})
	if err != nil {
		t.Fatal("Failed adding item", err)
	}

	lh := aer.LeafHash()
	if !bytes.Equal(lh, LeafMerkleTreeHash([]byte("foo"))) {
		t.Fatal("Failed adding item")
	}

	for treeRoot == nil || treeRoot.TreeSize < 1 {
		treeRoot, err = log.TreeHead(ctx, Head)
		if err != nil {
			t.Fatal("Failure getting root hash")
		}
	}

	if !bytes.Equal(treeRoot.RootHash, LeafMerkleTreeHash([]byte("foo"))) {
		t.Fatal("Failed calculating tree root")
	}

	_, err = log.Add(ctx, &pb.LeafData{LeafInput: []byte("fooz")})
	if err != nil {
		t.Fatal("Failed adding item")
	}

	_, err = log.Add(ctx, &pb.LeafData{LeafInput: []byte("bar")})
	if err != nil {
		t.Fatal("Failed adding item")
	}

	_, err = log.Add(ctx, &pb.LeafData{LeafInput: []byte("baz")})
	if err != nil {
		t.Fatal("Failed adding item")
	}

	p, err := log.Add(ctx, &pb.LeafData{LeafInput: []byte("smez")})
	if err != nil {
		t.Fatal("Failed adding item")
	}

	treeRoot, err = p.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if treeRoot.TreeSize != 5 {
		t.Fatal("Failure getting root hash")
	}

	entries := make([]*pb.LeafData, treeRoot.TreeSize)
	for i := int64(0); i < treeRoot.TreeSize; i++ {
		entries[i], err = log.Entry(ctx, i)
		if err != nil {
			t.Fatal("Failure getting entry")
		}
	}

	if !verifyRootHash(entries, treeRoot.RootHash) {
		t.Fatal("Failure verifying root hash")
	}

	for i := 0; i < 200; i++ {
		p, err = log.Add(ctx, &pb.LeafData{LeafInput: []byte(fmt.Sprintf("foo %d", rand.Int()))})
		if err != nil {
			t.Fatal("Failed adding item")
		}
	}

	treeRoot, err = p.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if treeRoot.TreeSize != 205 {
		t.Fatal("Failure getting root hash")
	}

	cnt := 0
	for entry := range log.Entries(context.Background(), 0, treeRoot.TreeSize) {
		err = log.VerifyInclusion(ctx, treeRoot, LeafMerkleTreeHash(entry.LeafInput))
		if err != nil {
			t.Fatal("Failure verifiying inclusion")
		}
		cnt++
	}
	if cnt != 205 {
		t.Fatal("Failed to get all entries")
	}

	th3, err := log.TreeHead(ctx, 3)
	if err != nil {
		t.Fatal("Failure getting root hash")
	}

	th7, err := log.TreeHead(ctx, 7)
	if err != nil {
		t.Fatal("Failure getting root hash")
	}

	err = log.VerifyConsistency(ctx, th3, th7)
	if err != nil {
		t.Fatal("Failure to generate consistency between 3 and 7")
	}

	rootHashes := generateRootHashes(context.Background(), log.Entries(context.Background(), 0, treeRoot.TreeSize))
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
		p, err = log.Add(ctx, &pb.LeafData{LeafInput: []byte(fmt.Sprintf("foo %d", rand.Int()))})
		if err != nil {
			t.Fatal("Failed adding item")
		}
	}

	treeRoot, err = p.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if treeRoot.TreeSize != 405 {
		t.Fatal("Failure getting root hash")
	}

	rootHashes = generateRootHashes(context.Background(), log.Entries(context.Background(), 0, treeRoot.TreeSize))
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

func createCleanEmptyBatchMutatorService() pb.VerifiableDataStructuresServiceServer {
	db := &TransientHashMapStorage{}
	return (&LocalService{
		AccessPolicy: &AnythingGoesOracle{},
		Mutator: (&BatchMutator{
			Writer:     db,
			BatchSize:  1000,
			BufferSize: 100000,
			Timeout:    time.Millisecond * 10,
		}).MustCreate(),
		Reader: db,
	}).MustCreate()
}

func createCleanEmptyService() pb.VerifiableDataStructuresServiceServer {
	db := &TransientHashMapStorage{}
	return (&LocalService{
		AccessPolicy: &AnythingGoesOracle{},
		Mutator:      &InstantMutator{Writer: db},
		Reader:       db,
	}).MustCreate()
}

func expectErr(t *testing.T, exp, err error) {
	if exp != err {
		t.Fatalf("Wanted %s, got %s", exp, err)
	}
}

func expectErrCode(t *testing.T, c codes.Code, err error) {
	if err == nil {
		t.Fatalf("Wanting bad code")
	}
	s, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Bad error type")
	}
	if s.Code() != c {
		t.Fatalf("Bad error ")

	}
}

func TestPermissions(t *testing.T) {
	db := &TransientHashMapStorage{}
	c := &Client{Service: (&LocalService{
		Mutator: &InstantMutator{Writer: db},
		Reader:  db,
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
	}).MustCreate()}

	var err error
	var v *pb.LeafData
	ctx := context.TODO()

	_, err = c.Account("0", "secr3t").VerifiableLog("foo").Add(ctx, &pb.LeafData{LeafInput: []byte("bar")})
	expectErrCode(t, codes.PermissionDenied, err)

	_, err = c.Account("0", "secret").VerifiableLog("fofo").Add(ctx, &pb.LeafData{LeafInput: []byte("bar")})
	expectErrCode(t, codes.PermissionDenied, err)

	_, err = c.Account("1", "secret").VerifiableLog("foo").Add(ctx, &pb.LeafData{LeafInput: []byte("bar")})
	expectErrCode(t, codes.PermissionDenied, err)

	_, err = c.Account("0", "secret").VerifiableLog("foo").Add(ctx, &pb.LeafData{LeafInput: []byte("bar")})
	expectErr(t, nil, err)

	v, err = CreateRedactableJSONLeafData([]byte("{\"name\":\"adam\",\"dob\":\"100000\"}"))
	expectErr(t, nil, err)
	p, err := c.Account("0", "secret").VerifiableLog("foo").Add(ctx, v)
	expectErr(t, nil, err)

	_, err = p.Wait(ctx)
	expectErr(t, nil, err)

	// Test less fields
	resp, err := c.Account("0", "").VerifiableLog("foo").Entry(ctx, 1)
	expectErr(t, nil, err)
	st := string(resp.ExtraData)
	if !strings.Contains(st, "\"dob\":\"***REDACTED***") {
		t.Fatal("Expected redacted")
	}
	if !strings.Contains(st, "adam") {
		t.Fatal("Expected name")
	}
	if strings.Contains(st, "100000") {
		t.Fatal("Value should not appear (unless incredibly unlucky with random generator)")
	}

	// Test more fields
	resp, err = c.Account("0", "secret").VerifiableLog("foo").Entry(ctx, 1)
	expectErr(t, nil, err)
	st = string(resp.ExtraData)
	if strings.Contains(st, "\"dob\":\"***REDACTED***") {
		t.Fatal("Not expected redacted")
	}
	if !strings.Contains(st, "adam") {
		t.Fatal("Expected name")
	}
	if !strings.Contains(st, "100000") {
		t.Fatal("Value should appear")
	}
}

func runSmokeTests(c pb.VerifiableDataStructuresServiceServer, t *testing.T) {
	// First wrap it in REST
	go StartRESTServer(&pb.ServerConfig{
		InsecureServerForTesting: true,
		RestListenBind:           ":8092",
	}, c)
	time.Sleep(50 * time.Millisecond)

	// Get client to it
	restClient := (&HTTPRESTClient{
		BaseURL: "http://localhost:8092",
	}).MustDial()

	// Now wrap that in a gRPC server
	go StartGRPCServer(&pb.ServerConfig{
		InsecureServerForTesting: true,
		GrpcListenBind:           ":8081",
		GrpcListenProtocol:       "tcp4",
	}, restClient)
	time.Sleep(50 * time.Millisecond)

	// And grab a client for that
	d := (&GRPCClient{
		Address:        "localhost:8081",
		NoGrpcSecurity: true,
	}).MustDial()

	testLog(context.TODO(), t, d)
	testMap(context.TODO(), t, d)
}

func TestClientComms(t *testing.T) {
	runSmokeTests(createCleanEmptyService(), t)
}

func TestBatchMutator(t *testing.T) {
	d := createCleanEmptyBatchMutatorService()
	testLog(context.TODO(), t, d)
	testMap(context.TODO(), t, d)
}

// GenerateRootHashes is a utility function that emits a channel of root hashes
// given a channel of input values. This is useful for some unit tests.
func generateRootHashes(ctx context.Context, input <-chan *pb.LeafData) <-chan []byte {
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
				stack = append(stack, LeafMerkleTreeHash(b.GetLeafInput()))
			}

			for j := index; (j & 1) == 1; j >>= 1 {
				stack = append(stack[:len(stack)-2], NodeMerkleTreeHash(stack[len(stack)-2], stack[len(stack)-1]))
			}

			rh := stack[len(stack)-1]
			for j := len(stack) - 2; j >= 0; j-- {
				rh = NodeMerkleTreeHash(stack[j], rh)
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

func verifyRootHash(entries []*pb.LeafData, answer []byte) bool {
	stack := make([][]byte, 0)
	for i, b := range entries {
		stack = append(stack, LeafMerkleTreeHash(b.LeafInput))
		for j := i; (j & 1) == 1; j >>= 1 {
			stack = append(stack[:len(stack)-2], NodeMerkleTreeHash(stack[len(stack)-2], stack[len(stack)-1]))
		}
	}
	for len(stack) > 1 {
		stack = append(stack[:len(stack)-2], NodeMerkleTreeHash(stack[len(stack)-2], stack[len(stack)-1]))
	}
	return bytes.Equal(stack[0], answer)
}

// TestObjectsMeetReq simply includes objects that might compile, but not comply with APIs
// since possibly we didn't test them properly otherwise.
func TestObjectsMeetReq(t *testing.T) {
	var kr StorageReader
	var kw StorageWriter

	var m MutatorService

	var o AuthorizationOracle

	kr = &TransientHashMapStorage{}
	kw = &TransientHashMapStorage{}

	kr = &BoltBackedService{}
	kw = &BoltBackedService{}

	kr = &BadgerBackedService{}
	kw = &BadgerBackedService{}

	m = &InstantMutator{}
	m = (&BatchMutator{}).MustCreate()

	o = &AnythingGoesOracle{}
	o = &StaticOracle{}

	log.Println(kr, kw, m, o) // "use" these so that go compiler will be quiet
}
