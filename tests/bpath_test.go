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

package tests

import (
	"testing"

	"github.com/continusec/verifiabledatastructures/api"
)

func TestBPathLen(t *testing.T) {
	if api.BPath(nil).Length() != 0 {
		t.FailNow()
	}
	if api.BPath([]byte{0}).Length() != 256 {
		t.FailNow()
	}
	if api.BPath([]byte{1}).Length() != 1 {
		t.FailNow()
	}
	if api.BPath([]byte{255}).Length() != 255 {
		t.FailNow()
	}
}

func TestBPathSlicing(t *testing.T) {
	foo := api.BPathFromKey([]byte("foo"))

	bPathMatches(t, foo.Slice(30, 30), nil)
	bPathMatches(t, foo.Slice(0, 4), []bool{false, false, true, false})
	bPathMatches(t, foo.Slice(1, 5), []bool{false, true, false, true})
}

func TestBPathJoining(t *testing.T) {
	foo := api.BPathFromKey([]byte("foo"))

	bPathMatches(t, api.BPathJoin(foo.Slice(30, 30), api.BPathTrue), []bool{true})
	bPathMatches(t, api.BPathJoin(foo.Slice(1, 5), foo.Slice(2, 4)), []bool{false, true, false, true, true, false})
}

func bPathMatches(t *testing.T, b api.BPath, expected []bool) {
	if int(b.Length()) != len(expected) {
		t.FailNow()
	}

	for i := 0; i < len(expected); i++ {
		if expected[i] != b.At(uint(i)) {
			t.FailNow()
		}
	}
}

func TestKeyGeneration(t *testing.T) {
	foo := api.BPathFromKey([]byte("foo"))
	expected := []bool{false, false, true, false, true, true, false, false, false, false, true, false, false, true, true, false, true, false, true, true, false, true, false, false, false, true, true, false, true, false, true, true, false, true, true, false, true, false, false, false, true, true, true, true, true, true, true, true, true, true, false, false, false, true, true, false, true, false, false, false, true, true, true, true, true, true, true, true, true, false, false, true, true, false, false, true, true, false, true, true, false, true, false, false, false, true, false, true, false, false, true, true, true, true, false, false, false, false, false, true, true, true, false, true, false, false, true, true, false, false, false, false, false, true, false, false, false, false, false, true, false, false, true, true, false, true, false, false, false, false, false, true, false, false, true, true, false, true, false, false, false, false, true, false, false, false, true, false, true, true, false, true, false, true, true, true, false, false, false, false, false, true, true, false, false, true, false, false, true, false, false, false, false, false, true, true, true, false, true, true, true, true, true, true, true, false, true, false, false, false, false, false, true, true, true, true, true, false, false, true, true, false, false, false, true, false, true, false, false, true, false, true, true, true, true, false, true, false, false, false, true, false, false, false, false, true, true, false, false, false, true, false, false, true, true, false, false, true, true, false, true, true, true, false, false, true, true, true, true, false, true, false, true, true, true, false}

	bPathMatches(t, foo, expected)
}
