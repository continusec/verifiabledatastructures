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
	"fmt"
	"strings"
	"testing"

	"github.com/continusec/verifiabledatastructures/pb"

	"golang.org/x/net/context"
)

func mustCreateJSONEntry(t *testing.T, v []byte) *pb.LeafData {
	rv, err := JSONEntry(v)
	if err != nil {
		t.Fatal(err)
	}
	return rv
}
func mustCreateRedactableJSONEntry(t *testing.T, v []byte) *pb.LeafData {
	rv, err := RedactableJsonEntry(v)
	if err != nil {
		t.Fatal(err)
	}
	return rv
}

// Start a server on :8080 and run a set of client library tests against it.
// Remove the "go " on the first line to start and keep serving - useful when testing
// a different language client library against the same tests.
func TestStuff(t *testing.T) {
	mockServer := &proxyAndRecordHandler{
		Host:          "https://api.continusec.com",
		InHeaders:     []string{"Authorization", "X-Previous-LeafHash"},
		OutHeaders:    []string{"Content-Type", "X-Verified-TreeSize", "X-Verified-Proof"},
		Dir:           "testdata",
		FailOnMissing: true,
	}
	go runMockServer(":8080", mockServer)
	localClient := &VerifiableDataStructuresClient{
		Service: &HTTPRESTClient{BaseUrl: "http://localhost:8080"},
	}

	client := localClient.Account("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6")
	log := client.VerifiableLog("newtestlog")
	_, err := log.TreeHead(Head)
	if err != ErrNotFound {
		t.Fatal(err)
	}

	client = localClient.Account("7981306761429961588", "wrongcred")
	log = client.VerifiableLog("newtestlog")
	_, err = log.TreeHead(Head)
	if err != ErrNotAuthorized {
		t.Fatal(err)
	}

	client = localClient.Account("wrongaccount", "wrongcred")
	log = client.VerifiableLog("newtestlog")
	_, err = log.TreeHead(Head)
	if err != ErrNotFound {
		t.Fatal(err)
	}

	client = localClient.Account("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6")
	log = client.VerifiableLog("newtestlog")
	mockServer.IncrementSequence() // skip log creation test
	mockServer.IncrementSequence() // skip log creation test

	_, err = log.Add(&pb.LeafData{LeafInput: []byte("foo")})
	if err != nil {
		t.Fatal(err)
	}

	_, err = log.Add(mustCreateJSONEntry(t, []byte("{\"name\":\"adam\",\"ssn\":123.45}")))
	if err != nil {
		t.Fatal(err)
	}

	_, err = log.Add(mustCreateRedactableJSONEntry(t, []byte("{\"name\":\"adam\",\"ssn\":123.45}")))
	if err != nil {
		t.Fatal(err)
	}

	addResp, err := log.Add(&pb.LeafData{LeafInput: []byte("foo")})
	if err != nil {
		t.Fatal(err)
	}

	_, err = log.BlockUntilPresent(addResp.LeafHash())
	if err != nil {
		t.Fatal(err)
	}

	head, err := log.TreeHead(Head)
	if err != nil {
		t.Fatal(err)
	}
	if head.TreeSize != 3 {
		t.Fatal(head.TreeSize)
	}

	for i := 0; i < 100; i++ {
		_, err = log.Add(&pb.LeafData{LeafInput: []byte(fmt.Sprintf("foo-%d", i))})
		if err != nil {
			t.Fatal(err)
		}
	}

	head103, err := log.VerifiedTreeHead(head, Head)
	if err != nil {
		t.Fatal(err)
	}

	if head103.TreeSize != 103 {
		t.Fatal(err)
	}

	err = log.VerifyInclusion(head103, LeafMerkleTreeHash([]byte("foo27")))
	if err != ErrNotFound {
		t.Fatal(err)
	}

	inclProof, err := log.InclusionProof(head103.TreeSize, LeafMerkleTreeHash([]byte("foo-27")))
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyLogInclusionProof(inclProof, LeafMerkleTreeHash([]byte("foo-27")), head103)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyLogInclusionProof(inclProof, LeafMerkleTreeHash([]byte("foo-27")), head)
	if err != ErrVerificationFailed {
		t.Fatal(err)
	}

	head50, err := log.TreeHead(50)
	if err != nil {
		t.Fatal(err)
	}

	cons, err := log.ConsistencyProof(head50.TreeSize, head103.TreeSize)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyLogConsistencyProof(cons, head50, head103)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyLogConsistencyProof(cons, head, head103)
	if err != ErrVerificationFailed {
		t.Fatal(err)
	}

	inclProof, err = log.InclusionProof(10, LeafMerkleTreeHash([]byte("foo")))
	if err != nil {
		t.Fatal(err)
	}

	h10, err := log.VerifySuppliedInclusionProof(head103, inclProof, LeafMerkleTreeHash([]byte("foo")))
	if err != nil {
		t.Fatal(err)
	}

	if h10.TreeSize != 10 {
		t.Fatal(10)
	}

	ctx := context.TODO()

	count := 0
	err = log.VerifyEntries(ctx, nil, head103, func(ctx context.Context, idx int64, entry *pb.LeafData) error {
		entry.GetLeafInput() // TODO

		count++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if count != 103 {
		t.Fatal(err)
	}

	head1, err := log.TreeHead(1)
	if err != nil {
		t.Fatal(err)
	}

	count = 0
	err = log.VerifyEntries(ctx, head1, head103, func(ctx context.Context, idx int64, entry *pb.LeafData) error {
		entry.GetLeafInput() // TODO

		count++
		return nil
	})
	if err != ErrNotAllEntriesReturned {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal(count)
	}

	head3, err := log.TreeHead(3)
	if err != nil {
		t.Fatal(err)
	}

	count = 0
	err = log.VerifyEntries(ctx, head1, head3, func(ctx context.Context, idx int64, entry *pb.LeafData) error {
		entry.GetLeafInput() // TODO
		count++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatal(count)
	}

	count = 0
	err = log.VerifyEntries(ctx, head50, head103, func(ctx context.Context, idx int64, entry *pb.LeafData) error {
		entry.GetLeafInput() // TODO
		count++
		return nil
	})
	if count != 53 {
		t.Fatal(count)
	}
	if err != nil {
		t.Fatal(err)
	}

	err = log.VerifyInclusion(head103, LeafMerkleTreeHash(mustCreateJSONEntry(t, []byte("{    \"ssn\":  123.4500 ,   \"name\" :  \"adam\"}")).LeafInput))
	if err != nil {
		t.Fatal(err)
	}

	redEnt, err := log.Entry(2)
	if err != nil {
		t.Fatal(err)
	}

	dd := redEnt.GetLeafInput() //TODO
	if err != nil {
		t.Fatal(err)
	}

	if strings.Index(string(dd), "ssn") >= 0 {
		t.Fatal(-1)
	}

	if strings.Index(string(dd), "adam") < 0 {
		t.Fatal(-1)
	}

	err = log.VerifyInclusion(head103, LeafMerkleTreeHash(redEnt.LeafInput))
	if err != nil {
		t.Fatal(err)
	}

	client = localClient.Account("7981306761429961588", "allseeing")
	log = client.VerifiableLog("newtestlog")

	redEnt, err = log.Entry(2)
	if err != nil {
		t.Fatal(err)
	}

	dd = redEnt.GetLeafInput() // todo

	if strings.Index(string(dd), "123.45") < 0 {
		t.Fatal(-1)
	}

	if strings.Index(string(dd), "adam") < 0 {
		t.Fatal(-1)
	}

	err = log.VerifyInclusion(head103, LeafMerkleTreeHash(redEnt.LeafInput))
	if err != nil {
		t.Fatal(err)
	}

	vmap := client.VerifiableMap("nnewtestmap")
	_, err = vmap.TreeHead(Head)
	if err != ErrNotFound {
		t.Fatal(err)
	}

	mockServer.IncrementSequence() // skip map creation test
	mockServer.IncrementSequence() // skip map creation test

	_, err = vmap.Set([]byte("foo"), &pb.LeafData{LeafInput: []byte("foo")})
	if err != nil {
		t.Fatal(err)
	}

	_, err = vmap.Set([]byte("fiz"), mustCreateJSONEntry(t, []byte("{\"name\":\"adam\",\"ssn\":123.45}")))
	if err != nil {
		t.Fatal(err)
	}

	waitResp, err := vmap.Set([]byte("foz"), mustCreateRedactableJSONEntry(t, []byte("{\"name\":\"adam\",\"ssn\":123.45}")))
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		_, err = vmap.Set([]byte(fmt.Sprintf("foo%d", i)), &pb.LeafData{LeafInput: []byte(fmt.Sprintf("fooval%d", i))})
		if err != nil {
			t.Fatal(err)
		}
	}

	_, err = vmap.Delete([]byte("foo"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = vmap.Delete([]byte("foodddd"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = vmap.Delete([]byte("foo27"))
	if err != nil {
		t.Fatal(err)
	}

	mlHead, err := vmap.MutationLog().BlockUntilPresent(waitResp.LeafHash())
	if err != nil {
		t.Fatal(err)
	}

	if mlHead.TreeSize != 106 {
		t.Fatal(-2)
	}

	mrHead, err := vmap.BlockUntilSize(mlHead.TreeSize)
	if err != nil {
		t.Fatal(err)
	}

	if mrHead.MutationLog.TreeSize != 106 {
		t.Fatal(err)
	}

	entryResp, err := vmap.Get([]byte("foo"), mrHead.MutationLog.TreeSize)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyMapInclusionProof(entryResp, []byte("foo"), mrHead)
	if err != nil {
		t.Fatal(err)
	}

	dd = entryResp.Value.GetLeafInput() // TODO
	if len(dd) > 0 {
		t.Fatal(-10)
	}

	entryResp, err = vmap.Get([]byte("foo-29"), mrHead.MutationLog.TreeSize)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyMapInclusionProof(entryResp, []byte("foo-29"), mrHead)
	if err != nil {
		t.Fatal(err)
	}

	dd = entryResp.Value.GetLeafInput() // TODO
	if len(dd) > 0 {
		t.Fatal(-10)
	}

	entryResp, err = vmap.Get([]byte("foo29"), mrHead.MutationLog.TreeSize)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyMapInclusionProof(entryResp, []byte("foo29"), mrHead)
	if err != nil {
		t.Fatal(err)
	}

	dd = entryResp.Value.GetLeafInput() // TODO

	if string(dd) != "fooval29" {
		t.Fatal(-10)
	}

	mapState106, err := vmap.VerifiedLatestMapState(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = vmap.VerifiedMapState(mapState106, 0)
	if err != nil {
		t.Fatal(err)
	}

	mapState2, err := vmap.VerifiedMapState(mapState106, 2)
	if err != nil {
		t.Fatal(err)
	}

	if mapState2.TreeSize() != 2 {
		t.Fatal(2)
	}

	val, err := vmap.VerifiedGet([]byte("foo"), mapState2)
	if err != nil {
		t.Fatal(err)
	}
	dd = val.GetLeafInput() // TODO

	if string(dd) != "foo" {
		t.Fatal(3)
	}

	mockServer.IncrementSequence() // skip list logs test
	mockServer.IncrementSequence() // skip list maps test
	mockServer.IncrementSequence() // skip destroy map test
	mockServer.IncrementSequence() // skip destroy map test
	mockServer.IncrementSequence() // skip destroy log test
	mockServer.IncrementSequence() // skip destroy log test

	client = localClient.Account("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6")
	vmap = client.VerifiableMap("mapjson")
	ms3, err := vmap.VerifiedLatestMapState(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vmap.VerifiedGet([]byte("stdjson"), ms3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vmap.VerifiedGet([]byte("redjson"), ms3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vmap.VerifiedGet([]byte("xstdjson"), ms3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vmap.VerifiedGet([]byte("xredjson"), ms3)
	if err != nil {
		t.Fatal(err)
	}

	client = localClient.Account("7981306761429961588", "redacted")
	vmap = client.VerifiableMap("mapjson")
	ms3, err = vmap.VerifiedLatestMapState(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vmap.VerifiedGet([]byte("stdjson"), ms3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vmap.VerifiedGet([]byte("redjson"), ms3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vmap.VerifiedGet([]byte("xstdjson"), ms3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vmap.VerifiedGet([]byte("xredjson"), ms3)
	if err != nil {
		t.Fatal(err)
	}

	client = localClient.Account("7981306761429961588", "testupdate")
	vmap = client.VerifiableMap("loadtestmap2")
	_, err = vmap.Update([]byte("fooyo"), &pb.LeafData{LeafInput: []byte("bar")}, nil)
	if err != nil {
		t.Fatal(err)
	}
}
