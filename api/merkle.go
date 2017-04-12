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

import (
	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/pb"
)

/* MUST be pow2. Assumes all args are range checked first */
/* Actually, the above is a lie. If failOnMissing is set, then we fail if any values are missing.
   Otherwise we will return nil in those spots and return what we can. */
func (l *LocalService) fetchSubTreeHashes(kr KeyReader, log *pb.LogRef, ranges [][2]int64, failOnMissing bool) ([][]byte, error) {
	/*
		Deliberately do not always error check above, as we wish to allow
		for some empty nodes, e.g. 4..7. These must be picked up by
		the caller
	*/
	rv := make([][]byte, len(ranges))
	for i, r := range ranges {
		if (r[1] - r[0]) == 1 {
			m, err := l.lookupLeafNodeByIndex(kr, log, r[0])
			if err == nil {
				rv[i] = m.Mth
			} else {
				if failOnMissing {
					return nil, err
				}
			}
		} else {
			m, err := l.lookupTreeNodeByRange(kr, log, r[0], r[1])
			if err == nil {
				rv[i] = m.Mth
			} else {
				if failOnMissing {
					return nil, err
				}
			}
		}
	}

	return rv, nil
}

/* Assumes all args are range checked first */
func (l *LocalService) calcSubTreeHash(kr KeyReader, log *pb.LogRef, start, end int64) ([]byte, error) {
	r := make([][2]int64, 0, 8) // magic number bad - why did we do this?

	for start != end {
		k := client.CalcK((end - start) + 1)
		r = append(r, [2]int64{start, start + k})
		start += k
	}

	hashes, err := l.fetchSubTreeHashes(kr, log, r, true)
	if err != nil {
		return nil, err
	}

	if len(hashes) == 0 {
		return nil, ErrInvalidTreeRange
	}

	rv := hashes[len(hashes)-1]
	for i := len(hashes) - 2; i >= 0; i-- {
		rv = client.NodeMerkleTreeHash(hashes[i], rv)
	}

	return rv, nil
}

type vMapNode pb.MapNode

var defaultLeafValues = client.GenerateMapDefaultLeafValues()

func (mn *vMapNode) leftNodeHash() []byte {
	if len(mn.LeftHash) == 0 {
		return defaultLeafValues[BPath(mn.Path).Length()+1]
	}
	return mn.LeftHash
}

func (mn *vMapNode) rightNodeHash() []byte {
	if len(mn.RightHash) == 0 {
		return defaultLeafValues[BPath(mn.Path).Length()+1]
	}
	return mn.RightHash
}

// if len(mn.Datahash) > 0, then set the appropriate non-default left or right hash based on the full path.
// Otherwise, leave well alone.
func (mn *vMapNode) setLeftRightForData() error {
	if len(mn.DataHash) > 0 { // don't check nil, as datastore round trip sets an empty length bytearray instead
		rv := mn.DataHash
		var lastLeft, lastRight []byte
		var leftDef, rightDef bool
		for i, j := int(BPath(mn.RemainingPath).Length())-1, 256; i >= 0; i, j = i-1, j-1 {
			if BPath(mn.RemainingPath).At(uint(i)) {
				lastLeft, lastRight = defaultLeafValues[j], rv
				leftDef, rightDef = true, false
			} else {
				lastLeft, lastRight = rv, defaultLeafValues[j]
				leftDef, rightDef = false, true
			}
			if i > 0 {
				rv = client.NodeMerkleTreeHash(lastLeft, lastRight)
			}
		}
		if !leftDef {
			mn.LeftHash = lastLeft
		}
		if !rightDef {
			mn.RightHash = lastRight
		}
	}
	return nil
}

func (mn *vMapNode) calcNodeHash() []byte {
	return client.NodeMerkleTreeHash(mn.leftNodeHash(), mn.rightNodeHash())
}
