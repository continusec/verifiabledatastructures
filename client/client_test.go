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

	"golang.org/x/net/context"
)

// Start a server on :8080 and run a set of client library tests against it.
// Remove the "go " on the first line to start and keep serving - useful when testing
// a different language client library against the same tests.
func TestStuff(t *testing.T) {
	go runMockServer(":8080", &proxyAndRecordHandler{
		Host:          "https://api.continusec.com",
		InHeaders:     []string{"Authorization", "X-Previous-LeafHash"},
		OutHeaders:    []string{"Content-Type", "X-Verified-TreeSize", "X-Verified-Proof"},
		Dir:           "testdata",
		FailOnMissing: true,
	})
	localClient := DefaultClient.WithBaseUrl("http://localhost:8080/v1")

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
	err = log.Create()
	if err != nil {
		t.Fatal(err)
	}

	err = log.Create()
	if err != ErrObjectConflict {
		t.Fatal(err)
	}

	_, err = log.Add(&RawDataEntry{RawBytes: []byte("foo")})
	if err != nil {
		t.Fatal(err)
	}

	_, err = log.Add(&JsonEntry{JsonBytes: []byte("{\"name\":\"adam\",\"ssn\":123.45}")})
	if err != nil {
		t.Fatal(err)
	}

	_, err = log.Add(&RedactableJsonEntry{JsonBytes: []byte("{\"name\":\"adam\",\"ssn\":123.45}")})
	if err != nil {
		t.Fatal(err)
	}

	addResp, err := log.Add(&RawDataEntry{RawBytes: []byte("foo")})
	if err != nil {
		t.Fatal(err)
	}

	_, err = LogBlockUntilPresent(log, addResp)
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
		_, err = log.Add(&RawDataEntry{RawBytes: []byte(fmt.Sprintf("foo-%d", i))})
		if err != nil {
			t.Fatal(err)
		}
	}

	head103, err := LogVerifiedTreeHead(log, head, Head)
	if err != nil {
		t.Fatal(err)
	}

	if head103.TreeSize != 103 {
		t.Fatal(err)
	}

	err = LogVerifyInclusion(log, head103, &RawDataEntry{RawBytes: []byte("foo27")})
	if err != ErrNotFound {
		t.Fatal(err)
	}

	inclProof, err := log.InclusionProof(head103.TreeSize, &RawDataEntry{RawBytes: []byte("foo-27")})
	if err != nil {
		t.Fatal(err)
	}

	err = inclProof.Verify(head103)
	if err != nil {
		t.Fatal(err)
	}

	err = inclProof.Verify(head)
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

	err = cons.Verify(head50, head103)
	if err != nil {
		t.Fatal(err)
	}

	err = cons.Verify(head, head103)
	if err != ErrVerificationFailed {
		t.Fatal(err)
	}

	inclProof, err = log.InclusionProof(10, &RawDataEntry{RawBytes: []byte("foo")})
	if err != nil {
		t.Fatal(err)
	}

	h10, err := LogVerifySuppliedInclusionProof(log, head103, inclProof)
	if err != nil {
		t.Fatal(err)
	}

	if h10.TreeSize != 10 {
		t.Fatal(10)
	}

	ctx := context.TODO()

	count := 0
	err = LogVerifyEntries(ctx, log, nil, head103, RawDataEntryFactory, func(ctx context.Context, idx int64, entry VerifiableEntry) error {
		_, err := entry.Data()
		if err != nil {
			return err
		}
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
	err = LogVerifyEntries(ctx, log, head1, head103, JsonEntryFactory, func(ctx context.Context, idx int64, entry VerifiableEntry) error {
		_, err := entry.Data()
		if err != nil {
			return err
		}
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
	err = LogVerifyEntries(ctx, log, head1, head3, JsonEntryFactory, func(ctx context.Context, idx int64, entry VerifiableEntry) error {
		_, err := entry.Data()
		if err != nil {
			return err
		}
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
	err = LogVerifyEntries(ctx, log, head50, head103, RawDataEntryFactory, func(ctx context.Context, idx int64, entry VerifiableEntry) error {
		_, err := entry.Data()
		if err != nil {
			return err
		}
		count++
		return nil
	})
	if count != 53 {
		t.Fatal(count)
	}
	if err != nil {
		t.Fatal(err)
	}

	err = LogVerifyInclusion(log, head103, &JsonEntry{JsonBytes: []byte("{    \"ssn\":  123.4500 ,   \"name\" :  \"adam\"}")})
	if err != nil {
		t.Fatal(err)
	}

	redEnt, err := log.Entry(2, RedactedJsonEntryFactory)
	if err != nil {
		t.Fatal(err)
	}

	dd, err := redEnt.Data()
	if err != nil {
		t.Fatal(err)
	}

	if strings.Index(string(dd), "ssn") >= 0 {
		t.Fatal(-1)
	}

	if strings.Index(string(dd), "adam") < 0 {
		t.Fatal(-1)
	}

	err = LogVerifyInclusion(log, head103, redEnt)
	if err != nil {
		t.Fatal(err)
	}

	client = localClient.Account("7981306761429961588", "allseeing")
	log = client.VerifiableLog("newtestlog")

	redEnt, err = log.Entry(2, RedactedJsonEntryFactory)
	if err != nil {
		t.Fatal(err)
	}

	dd, err = redEnt.Data()
	if err != nil {
		t.Fatal(err)
	}

	if strings.Index(string(dd), "123.45") < 0 {
		t.Fatal(-1)
	}

	if strings.Index(string(dd), "adam") < 0 {
		t.Fatal(-1)
	}

	err = LogVerifyInclusion(log, head103, redEnt)
	if err != nil {
		t.Fatal(err)
	}

	vmap := client.VerifiableMap("nnewtestmap")
	_, err = vmap.TreeHead(Head)
	if err != ErrNotFound {
		t.Fatal(err)
	}

	err = vmap.Create()
	if err != nil {
		t.Fatal(err)
	}

	err = vmap.Create()
	if err != ErrObjectConflict {
		t.Fatal(err)
	}

	_, err = vmap.Set([]byte("foo"), &RawDataEntry{RawBytes: []byte("foo")})
	if err != nil {
		t.Fatal(err)
	}

	_, err = vmap.Set([]byte("fiz"), &JsonEntry{JsonBytes: []byte("{\"name\":\"adam\",\"ssn\":123.45}")})
	if err != nil {
		t.Fatal(err)
	}

	waitResp, err := vmap.Set([]byte("foz"), &RedactableJsonEntry{JsonBytes: []byte("{\"name\":\"adam\",\"ssn\":123.45}")})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		_, err = vmap.Set([]byte(fmt.Sprintf("foo%d", i)), &RawDataEntry{RawBytes: []byte(fmt.Sprintf("fooval%d", i))})
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

	mlHead, err := LogBlockUntilPresent(vmap.MutationLog(), waitResp)
	if err != nil {
		t.Fatal(err)
	}

	if mlHead.TreeSize != 106 {
		t.Fatal(-2)
	}

	mrHead, err := MapBlockUntilSize(vmap, mlHead.TreeSize)
	if err != nil {
		t.Fatal(err)
	}

	if mrHead.MutationLogTreeHead.TreeSize != 106 {
		t.Fatal(err)
	}

	entryResp, err := vmap.Get([]byte("foo"), mrHead.MutationLogTreeHead.TreeSize, RawDataEntryFactory)
	if err != nil {
		t.Fatal(err)
	}

	err = entryResp.Verify(mrHead)
	if err != nil {
		t.Fatal(err)
	}

	dd, err = entryResp.Value.Data()
	if err != nil {
		t.Fatal(err)
	}

	if len(dd) > 0 {
		t.Fatal(-10)
	}

	entryResp, err = vmap.Get([]byte("foo-29"), mrHead.MutationLogTreeHead.TreeSize, RawDataEntryFactory)
	if err != nil {
		t.Fatal(err)
	}

	err = entryResp.Verify(mrHead)
	if err != nil {
		t.Fatal(err)
	}

	dd, err = entryResp.Value.Data()
	if err != nil {
		t.Fatal(err)
	}

	if len(dd) > 0 {
		t.Fatal(-10)
	}

	entryResp, err = vmap.Get([]byte("foo29"), mrHead.MutationLogTreeHead.TreeSize, RawDataEntryFactory)
	if err != nil {
		t.Fatal(err)
	}

	err = entryResp.Verify(mrHead)
	if err != nil {
		t.Fatal(err)
	}

	dd, err = entryResp.Value.Data()
	if err != nil {
		t.Fatal(err)
	}

	if string(dd) != "fooval29" {
		t.Fatal(-10)
	}

	mapState106, err := MapVerifiedLatestMapState(vmap, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = MapVerifiedMapState(vmap, mapState106, 0)
	if err != nil {
		t.Fatal(err)
	}

	mapState2, err := MapVerifiedMapState(vmap, mapState106, 2)
	if err != nil {
		t.Fatal(err)
	}

	if mapState2.TreeSize() != 2 {
		t.Fatal(2)
	}

	val, err := MapVerifiedGet(vmap, []byte("foo"), mapState2, RawDataEntryFactory)
	if err != nil {
		t.Fatal(err)
	}
	dd, err = val.Data()
	if err != nil {
		t.Fatal(err)
	}
	if string(dd) != "foo" {
		t.Fatal(3)
	}

	logList, err := client.ListLogs()
	if err != nil {
		t.Fatal(err)
	}
	if len(logList) != 24 {
		t.Fatal(logList)
	}

	mapList, err := client.ListMaps()
	if err != nil {
		t.Fatal(err)
	}
	if len(mapList) != 15 {
		t.Fatal(mapList)
	}

	err = vmap.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	err = vmap.Destroy()
	if err != ErrObjectConflict {
		t.Fatal(err)
	}

	err = log.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	err = log.Destroy()
	if err != ErrObjectConflict {
		t.Fatal(err)
	}

	client = localClient.Account("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6")
	vmap = client.VerifiableMap("mapjson")
	ms3, err := MapVerifiedLatestMapState(vmap, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MapVerifiedGet(vmap, []byte("stdjson"), ms3, JsonEntryFactory)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MapVerifiedGet(vmap, []byte("redjson"), ms3, RedactedJsonEntryFactory)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MapVerifiedGet(vmap, []byte("xstdjson"), ms3, JsonEntryFactory)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MapVerifiedGet(vmap, []byte("xredjson"), ms3, RedactedJsonEntryFactory)
	if err != nil {
		t.Fatal(err)
	}

	client = localClient.Account("7981306761429961588", "redacted")
	vmap = client.VerifiableMap("mapjson")
	ms3, err = MapVerifiedLatestMapState(vmap, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MapVerifiedGet(vmap, []byte("stdjson"), ms3, JsonEntryFactory)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MapVerifiedGet(vmap, []byte("redjson"), ms3, RedactedJsonEntryFactory)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MapVerifiedGet(vmap, []byte("xstdjson"), ms3, JsonEntryFactory)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MapVerifiedGet(vmap, []byte("xredjson"), ms3, RedactedJsonEntryFactory)
	if err != nil {
		t.Fatal(err)
	}

	client = localClient.Account("7981306761429961588", "testupdate")
	vmap = client.VerifiableMap("loadtestmap2")
	_, err = vmap.Update([]byte("fooyo"), &RawDataEntry{RawBytes: []byte("bar")}, &RawDataEntry{})
	if err != nil {
		t.Fatal(err)
	}
}
