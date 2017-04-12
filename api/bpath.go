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

package api

import "crypto/sha256"

type BPath []byte

func (b BPath) Length() uint {
	if b == nil || len(b) == 0 { // normally len(b) will not be zero, except after RT to datastore
		return 0
	}
	// We are a PString, essentially, except 0 means 256 (use nil for real zero)
	l := uint(b[0])
	if l == 0 {
		return 256
	} else {
		return l
	}
}

func (b BPath) At(idx uint) bool {
	return ((b[1+(idx/8)] >> (7 - (idx % 8))) & 1) == 1
}

func (b BPath) Str() string {
	rv := ""
	l := b.Length()
	for i := uint(0); i < l; i++ {
		if b.At(i) {
			rv += "1"
		} else {
			rv += "0"
		}
	}
	return rv
}

var (
	BPathFalse = BPath([]byte{1, 0})
	BPathTrue  = BPath([]byte{1, 128})
)

func (b BPath) Slice(start, end uint) []byte {
	if end <= start {
		return nil
	}
	l := end - start
	rv := make([]byte, 1+1+((l-1)/8))
	if l == 256 {
		rv[0] = byte(0)
	} else {
		rv[0] = byte(l)
	}
	for i, j := start, uint(0); i < end; i, j = i+1, j+1 {
		if b.At(i) {
			rv[1+(j/8)] |= byte(1 << (7 - (j % 8)))
		}
	}

	return rv
}

func BPathJoin(a, b BPath) BPath {
	lA, lB := a.Length(), b.Length()
	if (lA + lB) == 0 {
		return nil
	}

	l := lA + lB

	rv := make([]byte, 1+1+((l-1)/8))
	if l == 256 {
		rv[0] = byte(0)
	} else {
		rv[0] = byte(l)
	}
	for i, j := uint(0), uint(0); i < lA; i, j = i+1, j+1 {
		if a.At(i) {
			rv[1+(j/8)] |= byte(1 << (7 - (j % 8)))
		}
	}
	for i, j := uint(0), lA; i < lB; i, j = i+1, j+1 {
		if b.At(i) {
			rv[1+(j/8)] |= byte(1 << (7 - (j % 8)))
		}
	}

	return rv
}

func BPathCommonPrefixLength(a, b BPath) uint {
	count := uint(0)
	lA, lB := a.Length(), b.Length()
	for (count < lA) && (count < lB) && (a.At(count) == b.At(count)) {
		count++
	}
	return count
}

func BPathFromKey(key []byte) BPath {
	h := sha256.Sum256(key)
	nm := len(h) * 8
	rv := make([]byte, 1+len(h))
	if nm == 256 { // yes, it always will be unless we change hash function for testing to something shorter
		rv[0] = 0
	} else {
		rv[0] = byte(nm)
	}
	copy(rv[1:], h[:])
	return BPath(rv)
}
