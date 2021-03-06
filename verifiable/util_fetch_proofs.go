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
	"context"

	"github.com/continusec/verifiabledatastructures/merkle"
	"github.com/continusec/verifiabledatastructures/pb"
)

func createNeededStack(start int64) [][2]int64 {
	path := merkle.Path(start, 0, start+1)
	rv := make([][2]int64, len(path))
	for i, p := range path {
		rv[len(path)-(1+i)] = p
	}
	return rv
}

/* MUST be pow2. Assumes all args are range checked first */
/* Actually, the above is a lie. If failOnMissing is set, then we fail if any values are missing.
   Otherwise we will return nil in those spots and return what we can. */
func fetchSubTreeHashes(ctx context.Context, kr KeyReader, lt pb.LogType, ranges [][2]int64, failOnMissing bool) ([][]byte, error) {
	/*
		Deliberately do not always error check above, as we wish to allow
		for some empty nodes, e.g. 4..7. These must be picked up by
		the caller
	*/
	rv := make([][]byte, len(ranges))
	for i, r := range ranges {
		if (r[1] - r[0]) == 1 {
			m, err := lookupLeafNodeByIndex(ctx, kr, lt, r[0])
			if err == nil {
				rv[i] = m.Mth
			} else {
				if failOnMissing {
					return nil, err
				}
			}
		} else {
			m, err := lookupTreeNodeByRange(ctx, kr, lt, r[0], r[1])
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
func calcSubTreeHash(ctx context.Context, kr KeyReader, lt pb.LogType, start, end int64) ([]byte, error) {
	r := make([][2]int64, 0, 8) // magic number bad - why did we do this?

	for start != end {
		k := merkle.CalcK((end - start) + 1)
		r = append(r, [2]int64{start, start + k})
		start += k
	}

	hashes, err := fetchSubTreeHashes(ctx, kr, lt, r, true)
	if err != nil {
		return nil, err
	}

	if len(hashes) == 0 {
		return nil, ErrInvalidTreeRange
	}

	rv := hashes[len(hashes)-1]
	for i := len(hashes) - 2; i >= 0; i-- {
		rv = merkle.NodeHash(hashes[i], rv)
	}

	return rv, nil
}

func isLeaf(mn *pb.MapNode) bool {
	return len(mn.LeafHash) != 0
}

func calcNodeHash(mn *pb.MapNode, depth uint) ([]byte, error) {
	if isLeaf(mn) {
		rv := mn.LeafHash
		// Must make i int, else we underflow on next line and never terminate
		for i := 255; i >= int(depth); i-- {
			if BPath(mn.Path).At(uint(i)) {
				rv = merkle.NodeHash(defaultLeafValues[i+1], rv)
			} else {
				rv = merkle.NodeHash(rv, defaultLeafValues[i+1])
			}
		}
		return rv, nil
	}

	var leftHash, rightHash []byte
	if mn.LeftNumber == 0 {
		leftHash = defaultLeafValues[depth+1]
	} else {
		leftHash = mn.LeftHash
	}
	if mn.RightNumber == 0 {
		rightHash = defaultLeafValues[depth+1]
	} else {
		rightHash = mn.RightHash
	}
	return merkle.NodeHash(leftHash, rightHash), nil
}
