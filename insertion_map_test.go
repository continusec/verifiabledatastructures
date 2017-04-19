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
	"context"
	"encoding/base64"
	"testing"
)

type mutRes struct {
	Mutation *MapMutation
	Result   string
}

/*func VerifyTree(t *testing.T, logid []byte, cache map[string]*MapNode, treeSize int64, path []byte) int {
	rv := 0

	nodeL, err := GetFromCache(&RawLog{LogID: logid}, cache, []*MNAddr{&MNAddr{TreeSize: treeSize, Path: path}}, nil)
	if err != nil {
		t.FailNow()
	}
	node := nodeL[0]

	if node.DataHash != nil { // we are a leaf
		rv = 1

		if node.LeftNumber != 0 {
			t.FailNow()
		}
		if node.RightNumber != 0 {
			t.FailNow()
		}
		if BPathLen(node.RemPath) == 0 {
			t.FailNow() // very unlikely to be correct
		}
	} else { // we are not a leaf
		if node.LeftNumber == 0 && node.RightNumber == 0 {
			if BPathLen(node.Path) != 0 {
				t.FailNow()
			}
		} else {
			leftConc, rightConc := 0, 0

			if node.LeftNumber != 0 {
				if node.LeftHash == nil {
					t.FailNow()
				}
				leftConc = VerifyTree(t, logid, cache, node.LeftNumber, BPathJoin(path, BPathFalse))
			}
			if node.RightNumber != 0 {
				if node.RightHash == nil {
					t.FailNow()
				}
				rightConc = VerifyTree(t, logid, cache, node.RightNumber, BPathJoin(path, BPathTrue))
			}

			if leftConc == 1 && rightConc == 1 {
				rv = 2
			}
			if leftConc == 2 || rightConc == 2 {
				rv = 2
			}

			if rv != 2 {
				t.FailNow()
			}
		}
	}

	return rv
}*/

func recreateBasedOnProof(key, value []byte, proof [][]byte) []byte {
	kp := BPathFromKey(key)
	t := LeafMerkleTreeHash(value)
	for i := int(kp.Length()) - 1; i >= 0; i-- {
		p := proof[i]
		if p == nil {
			p = defaultLeafValues[i+1]
		}
		if kp.At(uint(i)) {
			t = NodeMerkleTreeHash(p, t)
		} else {
			t = NodeMerkleTreeHash(t, p)
		}
	}
	return t
}

func doInclusionProofCheck(t *testing.T, vmap *VerifiableMap, key, val, rootHash []byte, treeSize int64) {
	proof, err := vmap.Service.MapGetValue(context.Background(), &MapGetValueRequest{
		Key:      key,
		Map:      vmap.Map,
		TreeSize: treeSize,
	})
	if err != nil {
		t.Fatal("Err", err)
	}

	if !bytes.Equal(val, proof.Value.LeafInput) {
		t.Fatal("Bad inclusion proof check")
	}

	calculated := recreateBasedOnProof(key, val, proof.AuditPath)
	if !bytes.Equal(calculated, rootHash) {
		t.Log("NO Match!", base64.StdEncoding.EncodeToString(calculated), base64.StdEncoding.EncodeToString(rootHash))
		t.FailNow()
	}
}

func processListOfMutations(t *testing.T, mutations []*mutRes, doAfter func(t *testing.T, vmap *VerifiableMap)) {
	vmap := (&VerifiableDataStructuresClient{Service: createCleanEmptyService()}).Account("999", "secret").VerifiableMap("foo")
	ctx := context.Background()
	var err error
	var last *MapSetValueResponse
	for _, mr := range mutations {
		last, err = vmap.Service.MapSetValue(ctx, &MapSetValueRequest{
			Map:      vmap.Map,
			Mutation: mr.Mutation,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	lth, err := vmap.MutationLog().BlockUntilPresent(last.LeafHash)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vmap.BlockUntilSize(lth.TreeSize)
	if err != nil {
		t.Fatal(err)
	}

	var mts *MapTreeState
	for i, mr := range mutations {
		mts, err = vmap.VerifiedMapState(mts, int64(i+1))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(mts.MapTreeHead.RootHash, decodeH(mr.Result)) {
			t.Fatal("Wrong root hash for mutation z. Got x expected y", i, base64.StdEncoding.EncodeToString(mts.MapTreeHead.RootHash), mr.Result)
		}
	}

	if doAfter != nil {
		doAfter(t, vmap)
	}
}

func ignoreErr(x []byte, err error) []byte {
	return x
}

func ignoreStrErr(x string, err error) string {
	return x
}

func decodeH(s string) []byte {
	r, _ := base64.StdEncoding.DecodeString(s)
	return r
}

func TestStrangeValueRetrieval(t *testing.T) {
	processListOfMutations(t, []*mutRes{
		&mutRes{ // 0
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("foo"),
				Value:  &LeafData{LeafInput: []byte("bar")},
			},
			Result: "HgoyuytptJC4IKIvqg0Z4xIb/88VCda7MmfCxnNw4Ok=",
		},
		&mutRes{ // 1
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("sp"),
				Value:  &LeafData{LeafInput: []byte("baz")},
			},
			Result: "6ITTYnPOhKCqugnDKJ2gyuR4uNeE7r40/faCmXC6tKg=",
		},
	}, func(t *testing.T, vmap *VerifiableMap) {
		doInclusionProofCheck(t, vmap, []byte("foo"), []byte("bar"), decodeH("HgoyuytptJC4IKIvqg0Z4xIb/88VCda7MmfCxnNw4Ok="), 1)
		doInclusionProofCheck(t, vmap, []byte("foo"), []byte("bar"), decodeH("6ITTYnPOhKCqugnDKJ2gyuR4uNeE7r40/faCmXC6tKg="), 2)
	})
}

func TestConsUpNewNodesWithDelete(t *testing.T) {
	processListOfMutations(t, []*mutRes{
		&mutRes{ // 0
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("foo"),
				Value:  &LeafData{LeafInput: []byte("bar")},
			},
			Result: "HgoyuytptJC4IKIvqg0Z4xIb/88VCda7MmfCxnNw4Ok=",
		},
		&mutRes{ // 1
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("foo"),
				Value:  &LeafData{LeafInput: []byte("baz")},
			},
			Result: "Gzf2A+qPyIbLhju/TQhl26kmnKOTMVwx2L51sLKvSWs=",
		},
		&mutRes{ // 2
			Mutation: &MapMutation{
				Action: "delete",
				Key:    []byte("blah"),
			},
			Result: "Gzf2A+qPyIbLhju/TQhl26kmnKOTMVwx2L51sLKvSWs=",
		},
		&mutRes{ // 3
			Mutation: &MapMutation{
				Action: "delete",
				Key:    []byte("foo"),
			},
			Result: "xmifEIEqCYCXbZUz2Dh1KCFmFZVn7DUVVxbBQTr1PWo=",
		},
		&mutRes{ // 4
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("biz"),
				Value:  &LeafData{LeafInput: []byte("baz")},
			},
			Result: "p1WoF6fy9nYLMm9g0yFW1Rxp/ptVVR2jcWDT8wI2vxQ=",
		},
		&mutRes{ // 5
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("foo"),
				Value:  &LeafData{LeafInput: []byte("bar")},
			},
			Result: "x/a56RrAztn/TPXeMGixTFGGBdWRmupP8G1gg97IgGs=",
		},
		&mutRes{ // 6
			Mutation: &MapMutation{
				Action: "delete",
				Key:    []byte("biz"),
			},
			Result: "HgoyuytptJC4IKIvqg0Z4xIb/88VCda7MmfCxnNw4Ok=",
		},
		&mutRes{ // 7
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("a"),
				Value:  &LeafData{LeafInput: []byte("1")},
			},
			Result: "sMhp6g1yzgvQroBrHQFOhy8Q1nzZ45hX1mp+vbt1X9Q=",
		},
		&mutRes{ // 8
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("b"),
				Value:  &LeafData{LeafInput: []byte("2")},
			},
			Result: "+0N6q3oZFDLhVu2M4kNJHpVKSTMdLVg2kuKsBng6AO0=",
		},
		&mutRes{ // 9
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("c"),
				Value:  &LeafData{LeafInput: []byte("3")},
			},
			Result: "iwSAaI6EjPzbkdoVgtZHOl5sJNxX79UZbhfz5SDGdfw=",
		},
		&mutRes{ // 10
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("d"),
				Value:  &LeafData{LeafInput: []byte("4")},
			},
			Result: "VmF/E5FnSrqB6AvXEG8F6c02XBIyeL/IoQvRTPeAkNI=",
		},
		&mutRes{ // 11
			Mutation: &MapMutation{
				Action: "delete",
				Key:    []byte("foo"),
			},
			Result: "cIr7GehQ1X9QezlwJZBohy9zbpNLJFVf5E+hGmjpo+s=",
		},
		&mutRes{ // 12
			Mutation: &MapMutation{
				Action: "delete",
				Key:    []byte("a"),
			},
			Result: "Bdk3QI6y4UmarcvRoXI2IXQGreprtWnwlixuAN25zpg=",
		},
		&mutRes{ // 13
			Mutation: &MapMutation{
				Action: "delete",
				Key:    []byte("d"),
			},
			Result: "r5+U+UD+z33weuL3uoJdXM6l02bzgDwK0tAluTg7DDk=",
		},
	}, nil)
}

func TestConsUpNewNodes(t *testing.T) {
	processListOfMutations(t, []*mutRes{
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("foo"),
				Value:  &LeafData{LeafInput: []byte("bar")},
			},
			Result: "HgoyuytptJC4IKIvqg0Z4xIb/88VCda7MmfCxnNw4Ok=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action:           "update",
				Key:              []byte("foo"),
				Value:            &LeafData{LeafInput: []byte("baz")},
				PreviousLeafHash: LeafMerkleTreeHash([]byte("")),
			},
			Result: "HgoyuytptJC4IKIvqg0Z4xIb/88VCda7MmfCxnNw4Ok=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action:           "update",
				Key:              []byte("foo"),
				Value:            &LeafData{LeafInput: []byte("baz")},
				PreviousLeafHash: LeafMerkleTreeHash([]byte("bar")),
			},
			Result: "Gzf2A+qPyIbLhju/TQhl26kmnKOTMVwx2L51sLKvSWs=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("foo"),
				Value:  &LeafData{LeafInput: []byte("baz")},
			},
			Result: "Gzf2A+qPyIbLhju/TQhl26kmnKOTMVwx2L51sLKvSWs=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("FOO"),
				Value:  &LeafData{LeafInput: []byte("bar")},
			},
			Result: "6qCfuFPurDllwzdljCrUc/Q+YByJ29tpsaT7w4PiESU=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("biz"),
				Value:  &LeafData{LeafInput: []byte("baz")},
			},
			Result: "WSVM9W5fXuWxbBNf7A6yps+geB+Eilh1dmD7c7RWvkI=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("biz"),
				Value:  &LeafData{LeafInput: []byte("boz")},
			},
			Result: "qGz8D8nIjhTuGguqvIVxTjxSGx/jSb2IWqW0ub2caac=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("yankee"),
				Value:  &LeafData{LeafInput: []byte("doodle")},
			},
			Result: "VgXfZuaC9OL6EQjqhFpkquK9WAMqn3vZZA5SakUU+5I=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("continusec"),
				Value:  &LeafData{LeafInput: []byte("ftw")},
			},
			Result: "vhne/xV0lxp0XAuIvuSQKbenOGA/ki1flqtvJFj0rZ8=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("awesome"),
				Value:  &LeafData{LeafInput: []byte("muffins")},
			},
			Result: "BqKRrv6wL8NRel7pPwiOtdHs5wggbOq2OQSJUSxTuHY=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("oldmacdonald"),
				Value:  &LeafData{LeafInput: []byte("hadafarm")},
			},
			Result: "nOuUsWf0qsa4lzEB2mX3ApEsLftbCf+Y1KsB2wSaU5U=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("eie"),
				Value:  &LeafData{LeafInput: []byte("io")},
			},
			Result: "Yjjen3VVtDz8a5RTUjjovw5RyYKECE5BCTjPn4eEW4E=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "set",
				Key:    []byte("shouldi"),
				Value:  &LeafData{LeafInput: []byte("testmore")},
			},
			Result: "xkZFCGkj0fntqmfrXSWwSxFFPB7nMVKyDcRH9yBIIJU=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action: "update",
				Key:    []byte("shouldi"),
				Value:  &LeafData{LeafInput: []byte("dontdoit")},
			},
			Result: "xkZFCGkj0fntqmfrXSWwSxFFPB7nMVKyDcRH9yBIIJU=",
		},
		&mutRes{
			Mutation: &MapMutation{
				Action:           "update",
				Key:              []byte("shouldi"),
				Value:            &LeafData{LeafInput: []byte("dodoit")},
				PreviousLeafHash: LeafMerkleTreeHash([]byte("testmore")),
			},
			Result: "cmlMaZRei7GrEIHBGu0xuJ+8It4N/JtxVnJ4DTQE0e4=",
		},
	}, nil)
}

func TestBoringConsUpNewNodes(t *testing.T) {
	processListOfMutations(t, []*mutRes{
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8882"), Value: &LeafData{LeafInput: []byte("v9391")}}, Result: "uNyV3m0Xhu+WAZMgBmIWsQ1gdMJri++aokKnnNKWe/g="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4751"), Value: &LeafData{LeafInput: []byte("v5616")}}, Result: "d4KWFHl9rLNaiPG1JrbptiRSGHwfBw/iu1TxkD1ydWU="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3043"), Value: &LeafData{LeafInput: []byte("v3902")}}, Result: "TVMtuc4o+0/zdJpUCm5vdiz5Lg3r8t2h4G7n8BCFCu4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5906"), Value: &LeafData{LeafInput: []byte("v7663")}}, Result: "vu9Owt57iG4GoqxMCIgNRpZSdSDESPx4aH/yB+3f1WU="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1484"), Value: &LeafData{LeafInput: []byte("v4009")}}, Result: "1AmxB3/iozexzCg6w+suMVvy1PblUIw1UWw5FhIeCrA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2993"), Value: &LeafData{LeafInput: []byte("v3765")}}, Result: "FVk07tlsCtKWFmahOPDC/t7QnM/9qIo5n0vIszx2lgU="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4933"), Value: &LeafData{LeafInput: []byte("v574")}}, Result: "O13iVQ67XVgFQIZKQMFlbytFpJsbCC2z7Gqjn5PTV0w="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3013"), Value: &LeafData{LeafInput: []byte("v9270")}}, Result: "uV62br+/iVWmhPhi+YzkNDZvTqc1B8dRoNZi8zeK7Jk="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3280"), Value: &LeafData{LeafInput: []byte("v4425")}}, Result: "CM41P3/unBiY/fI5JcYuPTqmkMfpAQXWTvwyDcZTwb8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6241"), Value: &LeafData{LeafInput: []byte("v1245")}}, Result: "kG78Z6VXCRPghH1GpTrGDUF9SCUpYiDbFqOoTvfR8Ho="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2940"), Value: &LeafData{LeafInput: []byte("v1401")}}, Result: "1VP1LpK8Z+aZFw6vcVleUtLtct3cG2bN/E99LG3/49M="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3516"), Value: &LeafData{LeafInput: []byte("v6769")}}, Result: "TSqhKabXs1H+KtHhbQlZj9cGgThh6NHYKVj7EMcU1Js="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3512"), Value: &LeafData{LeafInput: []byte("v5660")}}, Result: "ykWY93OyLXBUp78Z00wG0BOCyDwwOIGqqGGpwMJ/F/E="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k63"), Value: &LeafData{LeafInput: []byte("v9505")}}, Result: "P6rC2SmUysTI+KWlg42O4bY4qK/mbhkS47UXlqLer9Q="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5987"), Value: &LeafData{LeafInput: []byte("v2405")}}, Result: "4egt0N3M7Wd2pD0ZY6rIE4c3Fq5Ua9BFQ32vJKnKrm4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6925"), Value: &LeafData{LeafInput: []byte("v6689")}}, Result: "DQ/g8j5gAM3geJEJ2j5EI6Y89sQZTikEgX4GTSK5MAA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5719"), Value: &LeafData{LeafInput: []byte("v9003")}}, Result: "/gtK0xvfaBK468iCfVohmuFhOpsXp/sZsz0WBw2bBTI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8581"), Value: &LeafData{LeafInput: []byte("v8136")}}, Result: "LpE3yw7redDeFLTkFL601mrB4i5Gk2BcH2G+0JUY/HI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2247"), Value: &LeafData{LeafInput: []byte("v4016")}}, Result: "6Lplmkaka/AbtvmYac6pyJmSj+IkEDXCuwTWxgIxy/U="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3182"), Value: &LeafData{LeafInput: []byte("v6563")}}, Result: "dsIPtN5WcRWV6EA3H5whdDU09qkp7EOANpDzNI/UqPw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k225"), Value: &LeafData{LeafInput: []byte("v6005")}}, Result: "9uUw6oSPjCU/1Q+qa/YVPAcIP58vTIpf9cPjI09RSdw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3149"), Value: &LeafData{LeafInput: []byte("v5617")}}, Result: "8RJma1tbxylQpAbULouA+aJc2XmQz4ci0IL7jB6hVM0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3769"), Value: &LeafData{LeafInput: []byte("v2585")}}, Result: "nkMiRLVDwR5OlrEKzQh9lLzvGoZVIFowegsTp5JjvNs="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8473"), Value: &LeafData{LeafInput: []byte("v5355")}}, Result: "5HOUhghZ1j8JxkixaFP6Plos6S8GnGMwY3fs+tTGs+w="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k753"), Value: &LeafData{LeafInput: []byte("v151")}}, Result: "T4NDvOK2pQY3DuOkGvz9q4BksVApKgOr9ZCIkm6NLTI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9973"), Value: &LeafData{LeafInput: []byte("v7104")}}, Result: "J47OHTEbzkr+UyAbMf4RZBXuOE1esfnhuz8oI4Hqfeg="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9899"), Value: &LeafData{LeafInput: []byte("v7935")}}, Result: "XP7TfS4z1/D5QDup5R9XJvyezBPoe/SLGcjJim56dfA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7201"), Value: &LeafData{LeafInput: []byte("v3370")}}, Result: "KndVn7WENEi0pfmoFOAwqtqmhhU91FwEl3xKeIYtWF8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9351"), Value: &LeafData{LeafInput: []byte("v7522")}}, Result: "+B31AiF6I8AvG/ai9KNh2lDGy3Bdzw0Lv9zWZuFEDI8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k964"), Value: &LeafData{LeafInput: []byte("v1898")}}, Result: "I3GeeuY/JpeGo5qr9L871ytH8yvQYRKfxwI+S10UMiQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2357"), Value: &LeafData{LeafInput: []byte("v7772")}}, Result: "oz8QLKAsp23WvjFuiIcLIhr2bY+lr4+pUcxlEK+S5dA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k294"), Value: &LeafData{LeafInput: []byte("v8861")}}, Result: "vWZRgAeY8RZEamnBq+fdTUXEFfWKqeJthy9fr5inn4Q="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1972"), Value: &LeafData{LeafInput: []byte("v6953")}}, Result: "YcGrk47AQOl++1odGhPOBumvukrd3CKuKCJziHjeVsk="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k510"), Value: &LeafData{LeafInput: []byte("v117")}}, Result: "AqTVq4bTbG6h/hV83zwnxjzT1CRyShPxtSvQ+DsdKyQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9186"), Value: &LeafData{LeafInput: []byte("v1782")}}, Result: "lTFrDXBzNmpeEjb3HXUlMzU6YBXsTusDdas4GUpGV4A="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5923"), Value: &LeafData{LeafInput: []byte("v3696")}}, Result: "GsbyAsiHGQe1SI2QHfrBm6bbjd4C8Ano1iF9UXb+nMo="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8899"), Value: &LeafData{LeafInput: []byte("v4928")}}, Result: "miuOisRtUcC9lwkKkwvBllxNW7maDcTU8OFcyeg+g9k="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9695"), Value: &LeafData{LeafInput: []byte("v422")}}, Result: "+Tn0KPVdTUuyXdL+hXp7FdPfp6ZESFpsvxOwEnnY9kA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1067"), Value: &LeafData{LeafInput: []byte("v2907")}}, Result: "FxW6Pxdg0l05/xBZEo4Q26yDSCKoHDbnAuqZBE83HDs="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1491"), Value: &LeafData{LeafInput: []byte("v7608")}}, Result: "QttNHEqqN1z73KsN76XJPo6diZtr2EvBuwjzZyq5n40="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7168"), Value: &LeafData{LeafInput: []byte("v3650")}}, Result: "ZRQD5hDg7MMWCPsUHdE8ZMOBLmmo/l570hEuouPtdww="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2703"), Value: &LeafData{LeafInput: []byte("v1805")}}, Result: "nc8oEfqov0hrNz3KLpfBTkUCB1UFt/cjuIdWmhFdgdw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8818"), Value: &LeafData{LeafInput: []byte("v5279")}}, Result: "gkJf7hSBQTGskPoO/I8qxgMMreS5d0XRka4Hp0vdXjA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3966"), Value: &LeafData{LeafInput: []byte("v5272")}}, Result: "uT9PatTZsYMPd13fx0M+Fs6MSwGF5mVSazO8797Q7X4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8375"), Value: &LeafData{LeafInput: []byte("v975")}}, Result: "bvPWSw/glIq/GnjUAb+Nftg+3F1lp+AYNlqa77xiJe8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2353"), Value: &LeafData{LeafInput: []byte("v1103")}}, Result: "i7hD+FSj08iQ8J1i/20Rb6+r3lSgTLgLXb7whkYKWE4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1856"), Value: &LeafData{LeafInput: []byte("v6362")}}, Result: "KKvuCMoGaCPlowAYh+o3XhmW2aZxVF0Bkn338nGfgZo="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1725"), Value: &LeafData{LeafInput: []byte("v6556")}}, Result: "hUL9NbVQmxe4bZeWqX1u6cIakd5D3klvruuZyBwl6nw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1175"), Value: &LeafData{LeafInput: []byte("v7502")}}, Result: "tJq2DrI03fl0v0bgUAoV3amMIaC6ImDfAeLg3Zqkkdo="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6894"), Value: &LeafData{LeafInput: []byte("v1650")}}, Result: "sj7ZfAn5aTYEczuUvILbo77XzJDsXczbB7tXZRvV4TM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8321"), Value: &LeafData{LeafInput: []byte("v7715")}}, Result: "9ZbcWcn0Fm/Wn+HkbxJ97NtuKEVNAViOKQOyzsWErUY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4139"), Value: &LeafData{LeafInput: []byte("v9060")}}, Result: "Iby1aSj5qk2weE4yXrwccqel1QlT609kji7T0nCc0dE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8405"), Value: &LeafData{LeafInput: []byte("v8151")}}, Result: "Sxpxd1ROmfAwUlsGesA82KaV5MC34i93jEHfbABsG7Y="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2124"), Value: &LeafData{LeafInput: []byte("v5106")}}, Result: "ldUfkg5TMFBveGRUc2kgBF2j/vyvToG7jcXRZuxyOvw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1610"), Value: &LeafData{LeafInput: []byte("v2619")}}, Result: "0GFuH2B6qjKAaqPvKCC7E9JkUOSnHO4OiMpgq7DUjYM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k862"), Value: &LeafData{LeafInput: []byte("v1674")}}, Result: "F3KTsflhuBW/TReHIR3MFuJa6b+Uhosnm41UHSZ0fXM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k296"), Value: &LeafData{LeafInput: []byte("v500")}}, Result: "T9Ia5l/8WSwbooXGwQmx5QztMfVyqCcHxSGLM08yEHA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3839"), Value: &LeafData{LeafInput: []byte("v3")}}, Result: "GGcIBAy8QmMTBP1BMLCOWu9/CDG9aVvN+CXpzvxUVGg="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5958"), Value: &LeafData{LeafInput: []byte("v8666")}}, Result: "Erv2pOgRWzLR1lT2v/zhMK/nJlZ+43V8CajMcE8zRfQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9429"), Value: &LeafData{LeafInput: []byte("v2034")}}, Result: "cWSY5I4Y+U39HFdTDtrrfQ8tp4knRe1L17FvVJfEFj0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6696"), Value: &LeafData{LeafInput: []byte("v6114")}}, Result: "WRRlVCY8kBIGrpJwUY/tHRDDq+E7irkQRXvUA0pXeus="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4689"), Value: &LeafData{LeafInput: []byte("v5506")}}, Result: "KeBdaCkjwg/1YHwBk76R2NlrXZAN5QkQwRrNjsl2VUE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8995"), Value: &LeafData{LeafInput: []byte("v2885")}}, Result: "rbV8r/JbN9PXbxXwoBLPNRJ4QRqowSjPJZdLpV2rJgM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8077"), Value: &LeafData{LeafInput: []byte("v8004")}}, Result: "H9jV7to+xiRHBMg8NIIpwm2g6uKhZzkjU2sq51p0a2A="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6434"), Value: &LeafData{LeafInput: []byte("v7538")}}, Result: "0VJewGb4RMBB+alRL39BPjQFK49wpj3kx5eJDPItDgU="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8202"), Value: &LeafData{LeafInput: []byte("v593")}}, Result: "+JNkBh7O/3VxsWrqJqC6Z4UrYyrc1GdDN1R6gdmW0r0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2375"), Value: &LeafData{LeafInput: []byte("v2497")}}, Result: "s32DnIYQnKLy+pzxykAjD9Y0q822PEHycsmGN1HE1AM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5537"), Value: &LeafData{LeafInput: []byte("v6197")}}, Result: "Y5MLChnLfurx35PvmVafRk/gK0F7a2VDtkGI6qB9h14="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5594"), Value: &LeafData{LeafInput: []byte("v1478")}}, Result: "2LgOEBafjTeEy2SynMda85y3KtpuhK/GwR5M9W+Qpdw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9837"), Value: &LeafData{LeafInput: []byte("v12")}}, Result: "rOeIxsNZDRe0gT033to2fIxd0c4JO5Y5jDmMYO54B8Y="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k195"), Value: &LeafData{LeafInput: []byte("v5935")}}, Result: "QVYEieijRcp59Wzn8KWMTwrBwZA5lHCdoherRPOCQbI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9544"), Value: &LeafData{LeafInput: []byte("v2938")}}, Result: "qEjfBswR0JIUWS8BI+zpZtJ+eALEpXyUpqj7RrZBZqs="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4194"), Value: &LeafData{LeafInput: []byte("v8248")}}, Result: "vq1MGkLsZ6VsL7cz4+eT3kNIgbur82XqEUQ+Yc1KBGQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9952"), Value: &LeafData{LeafInput: []byte("v1407")}}, Result: "fJEgNK/iz0/LapPxsLacTWH9sHNSnK01NPdDaO3AwLo="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9128"), Value: &LeafData{LeafInput: []byte("v5098")}}, Result: "xmrT9y907v+uatxF8vHjbjiFKalze38dndhK2v0ERss="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6023"), Value: &LeafData{LeafInput: []byte("v826")}}, Result: "y1K93R1MpGEPMTYdOo64dAPja2QrFGpBkcdU5YEEkGw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5413"), Value: &LeafData{LeafInput: []byte("v8995")}}, Result: "iBqjXzA+JQ8/URMKFTXw3gIDDxR3+4ngCuvc7KwTUiY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3365"), Value: &LeafData{LeafInput: []byte("v3466")}}, Result: "OzYKfh81qweC6+UGo73t+YQxdFhfn4T1kcqcUfifQQ8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1737"), Value: &LeafData{LeafInput: []byte("v7567")}}, Result: "e44xspyjPEjynsSnz8rysnBqfTskpi4E3e1bDcIm4A0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2171"), Value: &LeafData{LeafInput: []byte("v8738")}}, Result: "+kDO5aEGnJNkM/SSkFi8LTVYTGboeF8BUl6XMVQgBco="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4754"), Value: &LeafData{LeafInput: []byte("v2278")}}, Result: "HMSb+Q/Ao59umCiK3Yk95kRFPZkj941h7tXF2oEWDOk="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3412"), Value: &LeafData{LeafInput: []byte("v6902")}}, Result: "7HOdmDUqJSxzBUvJXw8Uq8CmLw4E2wAsRbahCZksYGM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2190"), Value: &LeafData{LeafInput: []byte("v8025")}}, Result: "e1DvOqTAUUxEI3lhl2mk0UuqmF5KOvMUClJ6z7iy3Ow="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7989"), Value: &LeafData{LeafInput: []byte("v3858")}}, Result: "VfcFK7xoCch3n60vEKFZX0/8IswU3wySW9xpoVkb6P0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2443"), Value: &LeafData{LeafInput: []byte("v487")}}, Result: "kLUyi6baX9pKQHGQr5X5g7gwYs9XsXegOQ8u0wUJUtI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7907"), Value: &LeafData{LeafInput: []byte("v3263")}}, Result: "GM2KhVPMQ8h13J7aC1//yH2V+zlPkZwC1u5AqF2WzBo="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4747"), Value: &LeafData{LeafInput: []byte("v4808")}}, Result: "BLm/3iR58EPlKd6ahBJdD+SxDXWRZDbtF/CHAU7mREY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6201"), Value: &LeafData{LeafInput: []byte("v4470")}}, Result: "iyKYDtVJ8YAoJO+fUQyuCfZrBdL03QLxg3X8/seqK8s="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8244"), Value: &LeafData{LeafInput: []byte("v2521")}}, Result: "VF9dIDyQzfAjEKO7GnIfGKCzCcx8IZEpbJk+8zMlFP4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6069"), Value: &LeafData{LeafInput: []byte("v8282")}}, Result: "+4+Je3YFNir2mBOWtyObSalXmSY3Ney1czlKy/qDgYk="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3892"), Value: &LeafData{LeafInput: []byte("v7259")}}, Result: "SjnuYo+TNIQknnvGDqMKPq3BBGMci1fTTXCZ665qGbY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1189"), Value: &LeafData{LeafInput: []byte("v3028")}}, Result: "EhKQnzKfW+R8ErN3kQt0NrDiSzQbsXicCsNIdBUd7EQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6966"), Value: &LeafData{LeafInput: []byte("v7261")}}, Result: "e5uAXb+HDRBG9D659Rvif1szF18GMjVti89VKri6Y+Y="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1897"), Value: &LeafData{LeafInput: []byte("v2879")}}, Result: "4rLtEoEQUN0DdavFRaB2Ial2Mq/clZHtXcWHXZFQfP8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8235"), Value: &LeafData{LeafInput: []byte("v5694")}}, Result: "Oqhi0YIcDnmuUu6bN5qJN+Avw91APUT437ZCAhyOHeQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6304"), Value: &LeafData{LeafInput: []byte("v6530")}}, Result: "6ApF3F5Ppg73BfWQ8CIV+cDLPSgptCw/dlxlji2oAVw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6114"), Value: &LeafData{LeafInput: []byte("v8484")}}, Result: "uR7yPNoimDJSQgsz5EKA/MTizt8fK12ZBhGOXSTM9sM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4142"), Value: &LeafData{LeafInput: []byte("v4150")}}, Result: "G9KOHMde7p3sY8Aug3TtkQPhhfC07TzowdvbvcFOhuE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4205"), Value: &LeafData{LeafInput: []byte("v8644")}}, Result: "7GPSzaVrtyVlCQ4dxpi6UEGZDjUJ5PinDfttOf60mA8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k802"), Value: &LeafData{LeafInput: []byte("v5443")}}, Result: "dUye+p8xbxqEwUBnfDWB1Ki70DYClaIG5u0FOZBsTWE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4311"), Value: &LeafData{LeafInput: []byte("v5787")}}, Result: "bseXidDRp2UnuqtvHhgR6K1mrX6vOFIYlXrIi1DoHnA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9567"), Value: &LeafData{LeafInput: []byte("v3239")}}, Result: "Aok/sqmJGRndm4c9RIGEq4JawDzL27MuBHSq9HmzHC0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1436"), Value: &LeafData{LeafInput: []byte("v4197")}}, Result: "27q4/W9N+rlvzZn+qjixNVBMmfR0YcM3niIV85u7olM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9536"), Value: &LeafData{LeafInput: []byte("v4024")}}, Result: "wBpTUxOD5E3iPlfLMy5RbnzfN8doBCnX9Q9fQ3uQdIY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1833"), Value: &LeafData{LeafInput: []byte("v5636")}}, Result: "zuGeyXnFT+bomkIdOCa7Stvznq6C1XI8Bt4wisx3T7s="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k735"), Value: &LeafData{LeafInput: []byte("v4836")}}, Result: "DHzuKJDt8Js1MLwuPf4ba5Y1GBmASyiMHo0o0EuD9Y4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k974"), Value: &LeafData{LeafInput: []byte("v4614")}}, Result: "a7opstBmYKXFCjNZ6/2+pv4otRCqGOyglUBHzJCWR38="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8279"), Value: &LeafData{LeafInput: []byte("v3555")}}, Result: "t9AfYuKF2HOskVbJWJ8sYK4MsBrsPerFDQATlBLkVzE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8275"), Value: &LeafData{LeafInput: []byte("v3001")}}, Result: "usuxHsuDcAH+u74lrvdTjvhAIIbquFF6phn+Yv1pT0Y="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8971"), Value: &LeafData{LeafInput: []byte("v3898")}}, Result: "jFNU2/uYYK3o1wW2PilSE0W+8FSY50iYOHYPAJUgSg0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6092"), Value: &LeafData{LeafInput: []byte("v1768")}}, Result: "ZVu9Sr7d0B7N9N+PrPi8ed86x0oZLk+5xoFg9b4Wp+I="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k989"), Value: &LeafData{LeafInput: []byte("v4033")}}, Result: "boSbbOZg2t0/nt2g7HOxFgnPr04cR6qL8KIn6O9I/FE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4237"), Value: &LeafData{LeafInput: []byte("v9352")}}, Result: "DEaF8xRNGDALQa1Bd4fFgyh/NtAYykGZ11Eylob/PtI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8084"), Value: &LeafData{LeafInput: []byte("v6424")}}, Result: "rBrpc28hw1blq0cE/gPfTASaBtgv448OSyE0yFXVJJA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1154"), Value: &LeafData{LeafInput: []byte("v5828")}}, Result: "0XyTk8CPidGzxCjNyqoi8zWNnZBS4wFaerYds9Vpqg4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4855"), Value: &LeafData{LeafInput: []byte("v7164")}}, Result: "fJXEoln+xL8zobfT95UnA0zqZYUp3o8AHSb2L2CPoK4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1177"), Value: &LeafData{LeafInput: []byte("v3422")}}, Result: "8rW1eytjmglYQe6kTydijDxDLvjVpQlXZ7yDVISlUAc="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3042"), Value: &LeafData{LeafInput: []byte("v8019")}}, Result: "g60erDO52NC/8kDlg0BI2NcTADqlgPBy1cnQrMM8tYM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k306"), Value: &LeafData{LeafInput: []byte("v8473")}}, Result: "kVYtZhZHAmm+wXTYqwhD/5qJLeEd4MTVvnNH3gGetLA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4441"), Value: &LeafData{LeafInput: []byte("v2120")}}, Result: "rBPh1Dq+kBbXDvx5Ex5pp2kcWFtmvXcQMIfJqJB9Nnw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5141"), Value: &LeafData{LeafInput: []byte("v108")}}, Result: "qkZCdTcoObgSBxHjIYcBF8z4c2YRF8ddBlaLw1zT5Y4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9850"), Value: &LeafData{LeafInput: []byte("v6243")}}, Result: "AaR5lvUpJTePpHs0R/N2USIQQxk2TsAANCdmm/GWazI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1023"), Value: &LeafData{LeafInput: []byte("v2737")}}, Result: "jO61fLCn03rgP1n4Ze4HsYHIthTxhAMV/eqi/9Qz3ks="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6676"), Value: &LeafData{LeafInput: []byte("v7857")}}, Result: "Lx8l0ETvL8Uad6u/MQGTOxHqOTjD+o2fVNzRfjAySSc="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7961"), Value: &LeafData{LeafInput: []byte("v5152")}}, Result: "q2XcJTqPqjF1R72PMzPm+GSEgJyNemaSeScLXWe4DpY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8126"), Value: &LeafData{LeafInput: []byte("v1293")}}, Result: "lAU/BKBBm69R5VUT0ZY3gT1zq1lU7X+EU8WP4BQ3F4w="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6998"), Value: &LeafData{LeafInput: []byte("v3092")}}, Result: "b6ce6OOdCdsjDosjZebtjb99rNJIgwL+57JByhHuAUg="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5172"), Value: &LeafData{LeafInput: []byte("v8673")}}, Result: "w3UFS+UPlOkuqNOGZbxMQ/SBymda6rSwgccg/SNdjsw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1577"), Value: &LeafData{LeafInput: []byte("v8099")}}, Result: "BXmSQ53QUqgmhvz0hoqzew27gDCDToN8/b0N6MmmL6I="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3419"), Value: &LeafData{LeafInput: []byte("v8130")}}, Result: "gI7WT0kioRPyKwYEC536o+ym31pvU5ADc6+5ngGtgGk="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5432"), Value: &LeafData{LeafInput: []byte("v9114")}}, Result: "5TCnQS2gzW8dkUR1ToyHaDAFSz/5uyKmT8vLctE5fQQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9409"), Value: &LeafData{LeafInput: []byte("v2338")}}, Result: "iGfyzp9Y3Jl1twcA1bov4eT2YKTtZ0Kg0aISdNUPWds="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k251"), Value: &LeafData{LeafInput: []byte("v8432")}}, Result: "b5zvjpeGu/dXGg8hAPRmCKdVfgDpS9xc9jXC+4kzS9g="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3336"), Value: &LeafData{LeafInput: []byte("v9118")}}, Result: "aTnkYevd17lpFP4Pgb6C8XtVwsDhpzfOwNzxnT14oi8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8042"), Value: &LeafData{LeafInput: []byte("v9608")}}, Result: "FDMYnIMKLVIIdvzv5f6AXzeunG28XlxVnqVZ2N6v52I="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2402"), Value: &LeafData{LeafInput: []byte("v4935")}}, Result: "c4G53Z6rael13re2qQAG52b46JqisLEIx6vGXM8D8IU="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4088"), Value: &LeafData{LeafInput: []byte("v9419")}}, Result: "A9UnEJ2q3gzoHnBFuMsmmUfrAMtosaz/ivoKOONPKiQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7255"), Value: &LeafData{LeafInput: []byte("v5511")}}, Result: "uQ8V/RdUwBvoNPErWOT7MwWhKTrBtHQiZqSfz/s0E/c="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9160"), Value: &LeafData{LeafInput: []byte("v1672")}}, Result: "S30QW5J2viiq/Z+0aO+ojPZhX0DlpCrBVV3mnolxtVs="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3787"), Value: &LeafData{LeafInput: []byte("v621")}}, Result: "I+egmeGce6CoMXbpalRzc9JxDI9jXLvML9VPzAmpJ44="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9025"), Value: &LeafData{LeafInput: []byte("v9280")}}, Result: "PBNu/o9XbrRbKrV729tYxOVvMAMaWiubb5Wa2BqBbAM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3061"), Value: &LeafData{LeafInput: []byte("v4759")}}, Result: "ItmCAeUADDgYuAUtE94jFqieGTtoFr6WPgZ8WLiiqGI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6005"), Value: &LeafData{LeafInput: []byte("v4036")}}, Result: "TSMIam8nnL7Kje2piRm4OUAJhRsMRlbvOR7gQlT289Q="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7223"), Value: &LeafData{LeafInput: []byte("v3172")}}, Result: "zSr060H4MZFfCEARqJEsuvcliJkM0YB0bq3zve2rr1A="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4353"), Value: &LeafData{LeafInput: []byte("v8462")}}, Result: "Um7BoOOzR1WtMh2zAV3uiSgARYpaav40kLdjm7tzNno="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3448"), Value: &LeafData{LeafInput: []byte("v6881")}}, Result: "eXfhLwkanznmvjC/gz+x+4BoAxKeuIDwnYC9CYTDMe0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3998"), Value: &LeafData{LeafInput: []byte("v5599")}}, Result: "z57iR3FghgngrevhlLSGTPwPYX3GjdYxu6D8nx9I2Zc="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k645"), Value: &LeafData{LeafInput: []byte("v646")}}, Result: "qMww7qQbcirLpczENsrgJ3964GAgBumh0ZCHbhIQlRE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8923"), Value: &LeafData{LeafInput: []byte("v1900")}}, Result: "VR3dTO6NM2uqeYZot36irHCaJRVixbpEzQjFOxazoR0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6196"), Value: &LeafData{LeafInput: []byte("v762")}}, Result: "2ts070lLgfXgQa0Egvue9iCwR8P0IdG9fsS0D6G+A3M="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9669"), Value: &LeafData{LeafInput: []byte("v4877")}}, Result: "e2V47crj2DIaJNPlwptb35DLJvJ4ZVxRaJBabOOryRE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5188"), Value: &LeafData{LeafInput: []byte("v9521")}}, Result: "1F3zOdz//hXgEUAPIQiIIcheb0yRpZneMHt85U9GKSI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8769"), Value: &LeafData{LeafInput: []byte("v8848")}}, Result: "SfGGGssg3/3oK4UoGRLJ8r9ZQnsGSCTsRj0A7uccYt4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3208"), Value: &LeafData{LeafInput: []byte("v9304")}}, Result: "E2ucPcNw+wSLvcKbLNFXZPhszdfuEYsPjQOtnNwj2Go="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1482"), Value: &LeafData{LeafInput: []byte("v3724")}}, Result: "bwGRs/lArNiwTpvS6qGvjnGkRg7EsMdzIB1aQeVu+tE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k205"), Value: &LeafData{LeafInput: []byte("v1661")}}, Result: "jqrtKtm0Wf8XqRc2UZ0W1z/aRjrImWDONMQ42VIQzpY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5097"), Value: &LeafData{LeafInput: []byte("v3339")}}, Result: "vFFHn+b8e19vUGs8jf1RfldHdouq1Ly/00VeXGBa/DE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1509"), Value: &LeafData{LeafInput: []byte("v2872")}}, Result: "gKhE13/IXiqna+CktJQY7PSJPhG5VaiJqimwBqIUSjo="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5940"), Value: &LeafData{LeafInput: []byte("v5276")}}, Result: "nZ6QKcUr59xKvIf9HwqdYn0iflpFAYAALh0/JSkKeGE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3464"), Value: &LeafData{LeafInput: []byte("v9958")}}, Result: "iUvFemZSCBKuuiaTgexgW41ofzgRUQSFMCYQkkBT9TM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4178"), Value: &LeafData{LeafInput: []byte("v1557")}}, Result: "Nnv9Im2PGslgtsLT/yE0ydr8ePAWE/lknog1pM8AnYw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5826"), Value: &LeafData{LeafInput: []byte("v3077")}}, Result: "BYaIBK+JoSWXho8RlFDVCKu3nOOabMh7go3ZO6Iehaw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9863"), Value: &LeafData{LeafInput: []byte("v5296")}}, Result: "Hjb/xQ5TJXDEnoBJS0HsD6zDu7/X046gEBzLhLkv2R8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2539"), Value: &LeafData{LeafInput: []byte("v3451")}}, Result: "838sVKu83d38h1rJxQ/X5hMVPdXQ+9O/UIGlh3/tryA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1411"), Value: &LeafData{LeafInput: []byte("v3199")}}, Result: "kW19J2LIfkbmpascjxuwHO+uAjsLQ3qJSO51ovq8t3g="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5778"), Value: &LeafData{LeafInput: []byte("v1206")}}, Result: "+ZfF5d/CdKt3LjxdQt2rJQrTBpruUVGASakZOrg4h3w="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2229"), Value: &LeafData{LeafInput: []byte("v4385")}}, Result: "6SJhkYZ+RvPht2UKR9xAPDuW5ahvTHiuBzGK6HBfwOs="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7097"), Value: &LeafData{LeafInput: []byte("v5000")}}, Result: "buqo1y1Cgh2wI1V/1wncWLn+RqFNIwbCqeUd9iDKzrs="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3264"), Value: &LeafData{LeafInput: []byte("v2720")}}, Result: "GeigE3BxsTTSuDYLaQmET3m33gxq6gjjjNEEKJWYVnQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6297"), Value: &LeafData{LeafInput: []byte("v963")}}, Result: "w3TEEb/1Jzsze1PTlO8f/m5u8dIGLj9HiBoS6mKAqrI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5049"), Value: &LeafData{LeafInput: []byte("v8763")}}, Result: "yv2Tlr74ls7/BplAblZCcAtfjrjM5SACTeyqm4vn0mY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7996"), Value: &LeafData{LeafInput: []byte("v2212")}}, Result: "c1c+OdLgJt+GRyOYLqBJpjKQI+uKkHC7f/WS5b0c/x8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4704"), Value: &LeafData{LeafInput: []byte("v7109")}}, Result: "JGoej2CVrNgXgTv+g6EkT4cQZErQ1lK0CsO4ooyhg2U="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6971"), Value: &LeafData{LeafInput: []byte("v7764")}}, Result: "r2G+AsqSLOCrVoOAMxTRGSlkyvz7GXfYuz1kaWCgPyY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6117"), Value: &LeafData{LeafInput: []byte("v6495")}}, Result: "LbqzqcCgFIY19/TeFXL7RsJdQQiz1feU/mJE6NwYn7I="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k581"), Value: &LeafData{LeafInput: []byte("v47")}}, Result: "L8YJtF7tPyNmYG288QXtBpKkFNC1rCjIXraF0gEKAwE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7356"), Value: &LeafData{LeafInput: []byte("v81")}}, Result: "vlSwRZaMso7I/2iF18Z8BTF7dokLyjUOvFX8+9E7S+0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1794"), Value: &LeafData{LeafInput: []byte("v2513")}}, Result: "T1GXQovpSBYPbUrEjYkti1+vvb3p8xyjEPoUeEV3PIs="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4874"), Value: &LeafData{LeafInput: []byte("v8703")}}, Result: "NoWyoXktWIUCwKuI85zdZjIsWQJPrt7hQSeV6l7ijlI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4500"), Value: &LeafData{LeafInput: []byte("v9051")}}, Result: "FpiyXiq620uIZyAxgTEVSowbDyBxXB/cbLhNuyOp+cw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5438"), Value: &LeafData{LeafInput: []byte("v1966")}}, Result: "uSf9wofHn/hQlJ2rJ/gdSdN/YajW2EF2zl/Rc1H6FQc="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k568"), Value: &LeafData{LeafInput: []byte("v5801")}}, Result: "ex9UKXtxo2QD9BVxNnsNS5XW8BHcpv7WAHauMgphzZ8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7217"), Value: &LeafData{LeafInput: []byte("v7163")}}, Result: "lOt3NiYNB267awDouVJGAxCmj/q7VD5Z0BaIbXzU1Jg="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6969"), Value: &LeafData{LeafInput: []byte("v2592")}}, Result: "T59AwwNw3ngbaVNEJpCNJXtB1a8b09Yqh/QQhsV8blI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9676"), Value: &LeafData{LeafInput: []byte("v4295")}}, Result: "JogPL+Bf26+ct35p+A213qFn93prcW40Op9TtutbXaA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1810"), Value: &LeafData{LeafInput: []byte("v1992")}}, Result: "0/O2eEeV+BhyoopZwpiZq8Q7E5HvISslVVHadoWMt8o="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k151"), Value: &LeafData{LeafInput: []byte("v805")}}, Result: "jVN7HThGUGdXGQ1A8oqxwbECHaRmBD+Tt+3ge21cMOc="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1424"), Value: &LeafData{LeafInput: []byte("v6363")}}, Result: "hou2uFptysOGj43yoVrCwb/qZjblYQRDhI+S1D9+hiU="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4788"), Value: &LeafData{LeafInput: []byte("v222")}}, Result: "1/lYHwW7kJxMuKoCjO2AsYob/tGfhQxedlGJAX6wc5s="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7914"), Value: &LeafData{LeafInput: []byte("v3856")}}, Result: "XSbHJlon5hUMvSZILOCkrDBbfsC9twr5x3tMJqkOK4Q="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2101"), Value: &LeafData{LeafInput: []byte("v965")}}, Result: "WTciUT1KJ3JCzxBBgcBMNHot14vjBDKm5Bah2uLmhSg="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k775"), Value: &LeafData{LeafInput: []byte("v5700")}}, Result: "HAjTnYD307XSCjATrYSgRD2OEjJR55gplCmHNfBpiac="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k714"), Value: &LeafData{LeafInput: []byte("v294")}}, Result: "9g42wXqod5iwu9I8ifvkMEyhN+PCNlnwinFXgrvNw5M="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4380"), Value: &LeafData{LeafInput: []byte("v9385")}}, Result: "GFBKZ4xj93dqlhwkPqhcKfhaWz5HWXkET+elxZaxgu0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6368"), Value: &LeafData{LeafInput: []byte("v414")}}, Result: "dQLAJnDgRKkNjJtISXwl4czt48xqVpw9dQSOJbcugAM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4241"), Value: &LeafData{LeafInput: []byte("v3297")}}, Result: "YDwEDRyY46FsxEEcnH9iVVWlLbvVocAuzjyE8fr6baI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1101"), Value: &LeafData{LeafInput: []byte("v9272")}}, Result: "Rb9U9x+LR/rxmNYv7feK4F/7cA2SSITj7zTWvPC2PWE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1000"), Value: &LeafData{LeafInput: []byte("v7669")}}, Result: "H+exx1Uc3vXkOYRPN4cKHXGnkhfwSHjvu7be92E1TPA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6652"), Value: &LeafData{LeafInput: []byte("v5892")}}, Result: "HXL2EkVVCFia/xXuPEyclnF/b9uEHHFxEUqgjv2vOdw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k834"), Value: &LeafData{LeafInput: []byte("v1614")}}, Result: "TxmOCo3hy62jJ/75sTVluaplM6QZt/LJObLhcTVQ3ck="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4908"), Value: &LeafData{LeafInput: []byte("v1275")}}, Result: "SVPiSz7EMWIx1BPwPXYpbn/iS95/lO5pcxapQqFnyFc="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3334"), Value: &LeafData{LeafInput: []byte("v4380")}}, Result: "9JvIDPI7Ji1paTzS4546GhaNKHVNw0/f7hO6XY9WqH8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8435"), Value: &LeafData{LeafInput: []byte("v6971")}}, Result: "tDRy3zEsm2nU3An/Qz5QJF5E5OIL3e1vK4tZ1b/dXgI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4629"), Value: &LeafData{LeafInput: []byte("v9009")}}, Result: "tGLY0TbNbu0bXNzHw9qhQ/+D45rO2MpYvW6KSRU8HBM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2977"), Value: &LeafData{LeafInput: []byte("v4329")}}, Result: "PzwHmGK2U4+n4cIPQCIxOtfKKQ0+Ec0YDHEmVht+9go="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1828"), Value: &LeafData{LeafInput: []byte("v863")}}, Result: "5Zs0TI0XskF4EmLzYKhPwEcqozu8HuBNQJUEbp9SQCw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k807"), Value: &LeafData{LeafInput: []byte("v687")}}, Result: "DmMw2y3GaewXB6ymhrJEDFlN4wOe0Q1VrhhWb7ghjrY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7274"), Value: &LeafData{LeafInput: []byte("v1906")}}, Result: "k4yOISGm5i+0WZzF1OihMrjrBu8xwd6ntQXwMlHsJTw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3796"), Value: &LeafData{LeafInput: []byte("v4420")}}, Result: "/Fi8b/I4Za53lUkHZIFVwouB8vD5goan63E/YOG3gdE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5114"), Value: &LeafData{LeafInput: []byte("v460")}}, Result: "ZlDY0EqtGgbxYSCprWcaOw1UJ0MdjWbD5SEmjHMyqRQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9730"), Value: &LeafData{LeafInput: []byte("v4963")}}, Result: "ejW/LnRAxzleHiWb/ta3ZDehDQuTV8iSFJ0Y579n6OU="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6239"), Value: &LeafData{LeafInput: []byte("v6855")}}, Result: "CvIY2Wcqr8Ncu+FUucazYCepzJ70nTZqnQut4lFWQUA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7280"), Value: &LeafData{LeafInput: []byte("v145")}}, Result: "ZhLve9FdrVYUSIL+EW2lOzjtmAkKAtRPCekOBq472oM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2366"), Value: &LeafData{LeafInput: []byte("v83")}}, Result: "qqxzRzjlP55ihE+Dflo2/9RdTw67l/6MuseHdSv9QtI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8184"), Value: &LeafData{LeafInput: []byte("v3867")}}, Result: "lRtkM4k8/KNmTCGs0UR6OWTqs4wX4VwBiJqgQUdET2Y="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9059"), Value: &LeafData{LeafInput: []byte("v8331")}}, Result: "k3ZGHLkhPJfmuPJ3tsJRij7Vz/saSwlbi2URbx0LaO8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3902"), Value: &LeafData{LeafInput: []byte("v5748")}}, Result: "7ySsrkem3a/Y5L/Z3C9nGX1H4FOvO6tAL/5N9m0YZag="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3031"), Value: &LeafData{LeafInput: []byte("v8287")}}, Result: "GG1QYdnB+i04iI0jx0ZSqNBRJAG3OGmRY489GdYTJyE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8015"), Value: &LeafData{LeafInput: []byte("v1107")}}, Result: "8KPk2HbupXc6QnIvXYLIP2J/iI/pvSWtE2p6iovA3LI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1179"), Value: &LeafData{LeafInput: []byte("v6030")}}, Result: "moadq6fQdtfAoMouuIOkcVKjTMZGV6laOxipWB0QusQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7299"), Value: &LeafData{LeafInput: []byte("v3684")}}, Result: "K87OiBLwnSzCX3wLkDZ4mQIRwrkAEA2E5HWea8jF2qQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k252"), Value: &LeafData{LeafInput: []byte("v1853")}}, Result: "UQFwnXeIOy65ZcNHjan148uPzxXaTqb+bEqgTHMu4QE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8906"), Value: &LeafData{LeafInput: []byte("v1292")}}, Result: "yoR8nkKMf+Piz7q+pzAQ7RmCB6FnTH6Sh01Xnwt+rCA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2357"), Value: &LeafData{LeafInput: []byte("v7775")}}, Result: "c/2bkZsbzz9BP6G8zQzjjBLF0xKh3s9vtbKZsKhbUlU="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3274"), Value: &LeafData{LeafInput: []byte("v5588")}}, Result: "XALWi6aPVywS5HiURV818pdGbwUU1diDQbyqSNp4Gao="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3051"), Value: &LeafData{LeafInput: []byte("v4877")}}, Result: "Kf2sK4XAT+OZzRu3xP1KMFbL2QfxB/zM6gab5GiRKeY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7905"), Value: &LeafData{LeafInput: []byte("v7504")}}, Result: "kwP88nWjcTaLLsdZRlon3K0B3WxWQr0oyDrUtkG0T+E="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5917"), Value: &LeafData{LeafInput: []byte("v6811")}}, Result: "pUcMF2UCI76Pgz9A4/A6P5qGWDV8BaQXAo+60HXmxZY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5276"), Value: &LeafData{LeafInput: []byte("v6283")}}, Result: "lQ5rsyVY82X5ebXc0UsIreMmO8alu2+YTmmgh3ztI1s="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4830"), Value: &LeafData{LeafInput: []byte("v4849")}}, Result: "g2ooW37zm8Nu3NZ3K9gO+eWs0q8Wlb2R5BztBWYlqS0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k122"), Value: &LeafData{LeafInput: []byte("v4999")}}, Result: "49nW4hjpbGvfGi+cuWfzF7eQhq5BoEEDDGhSgzsU8eM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1833"), Value: &LeafData{LeafInput: []byte("v6390")}}, Result: "7r69a75O8aJXvY4g9sLC3UIpbPG2Bko86dgqsT2D1so="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2026"), Value: &LeafData{LeafInput: []byte("v9293")}}, Result: "KKI3gGlvrBdfwJXA2K5aCs+wV0VY0Yv3G3hzHR4G7gs="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2182"), Value: &LeafData{LeafInput: []byte("v6547")}}, Result: "9O0xPPOcEohUR6LR7O5UiQTaYzGnHoloHd6hEWYv0pQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6065"), Value: &LeafData{LeafInput: []byte("v9793")}}, Result: "K4Ot8QOKUQto3vsJKk5OCZeYZrbjYpwdniqqKxA745k="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1661"), Value: &LeafData{LeafInput: []byte("v7242")}}, Result: "Vea0JVRPgGZuHs/6GoYiNW6kmppiJz0j8kyBrPxg0sU="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7949"), Value: &LeafData{LeafInput: []byte("v1332")}}, Result: "W4sF+dw5i+zIz2cMUfI6RW2huVMdDO6J8MQVzHTzQrM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9316"), Value: &LeafData{LeafInput: []byte("v312")}}, Result: "0kjwKBOVH4PWjgXPJUem0AV5hQM34RpWwabYPf1r0UA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7012"), Value: &LeafData{LeafInput: []byte("v1808")}}, Result: "CFLM5w1KC4LR04LavZ1+HJ6ynmGiCd5Yd6uGmANuTGs="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k483"), Value: &LeafData{LeafInput: []byte("v9348")}}, Result: "we2ENdJS7F0/htC/LnPO7k4/C566/98wXtm3b29TRk8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8638"), Value: &LeafData{LeafInput: []byte("v9133")}}, Result: "jTRC+tZ75NdPJsefEwqllVEjD8kswWY8TT20g2WxwtQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9706"), Value: &LeafData{LeafInput: []byte("v8316")}}, Result: "6B3RBCOBnyeh/HcAyn+jRUOITE43cGN87PtRaFnEeZM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9601"), Value: &LeafData{LeafInput: []byte("v2023")}}, Result: "czeTHTeGoelQmifPbaYzPLNd9BxrIWD7qy3IiDWUlK0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k290"), Value: &LeafData{LeafInput: []byte("v7938")}}, Result: "d345wXafjyonA2gUwpmSUP2rig830puRo5BOgBNLxk4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k46"), Value: &LeafData{LeafInput: []byte("v3880")}}, Result: "Kjcate88DAG6j5kcBpqA59WqjCdPZTFm7Ag9oAumGcs="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k5974"), Value: &LeafData{LeafInput: []byte("v7492")}}, Result: "e1+TqEPmzS4xHJseDIy4HZQN8WbN09cEhGhVtbhYHGw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3343"), Value: &LeafData{LeafInput: []byte("v9602")}}, Result: "rZogqk88y06L7WRQhSy69kAlrIxR6iinYhdUMlwHMM0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4429"), Value: &LeafData{LeafInput: []byte("v5978")}}, Result: "XQhCmkkb+VfDkkoeYbQbwiPuXO5nzW5oy6C48y/qp2E="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k463"), Value: &LeafData{LeafInput: []byte("v1086")}}, Result: "7ksu6S8F3ELgojDpUYK9oQFx4ejjpXh+RdAmhroCJ2c="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8091"), Value: &LeafData{LeafInput: []byte("v548")}}, Result: "KTK8ZmVGleXOyRu0uMeQ1o94izSrjKBrCpuMQjM6WL8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2036"), Value: &LeafData{LeafInput: []byte("v2407")}}, Result: "9UySPYg4mIlcGf/ZxAD5cLWQyWnwMxQSu5Q+ObamBcE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8598"), Value: &LeafData{LeafInput: []byte("v1926")}}, Result: "97SdID/ghdGGUWhr2L8UbxASOXOkMI5r+l38DL/UsLU="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1729"), Value: &LeafData{LeafInput: []byte("v5960")}}, Result: "mTi7ZkW1o35MRzJeL5aVVJiQ4ujIwfaRdmfR02ynflA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3657"), Value: &LeafData{LeafInput: []byte("v6776")}}, Result: "c9Y3vDeBdOgdaYvv91rgcXQtqbAq4FESXey82NJgIXg="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k46"), Value: &LeafData{LeafInput: []byte("v74")}}, Result: "MNj2PZ13mbXIDDCbpdm+IHRPOjrp/TKfiIhC4pMVcSk="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9615"), Value: &LeafData{LeafInput: []byte("v1490")}}, Result: "kAU9oEXltcMESjtmznL54ALZkXMllaDTEU5jr3NUKUo="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8708"), Value: &LeafData{LeafInput: []byte("v670")}}, Result: "NUVLkPYdu9I0YJRzYDBmNnigi9f28zPfl5Oh3o+0vHk="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7267"), Value: &LeafData{LeafInput: []byte("v2923")}}, Result: "QecYH/Q2k8hvCT/FuYNEM35yPY+ijpQrjbKmqNtvtFM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3527"), Value: &LeafData{LeafInput: []byte("v9973")}}, Result: "Z2JMV3qnoI3RkG8kJIQK2HVViLmtBY2L/u5NjoCnTZk="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k812"), Value: &LeafData{LeafInput: []byte("v7221")}}, Result: "VBY0LAmk4CTXvYSTdhQ72iHLc4w5T9s9S0k/wWoyAMc="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9473"), Value: &LeafData{LeafInput: []byte("v8417")}}, Result: "TGGC0X3DLrlANhwQ2S8Y4siAmaJHlSelDU0mrpd//aQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7509"), Value: &LeafData{LeafInput: []byte("v2815")}}, Result: "vPUjnUwFqB1mC1cdlL2NtPJ8tN71QzOcFVdbSrW1FjQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k6075"), Value: &LeafData{LeafInput: []byte("v5175")}}, Result: "S6ZsqbK5wEmHGj6yzttQbcOt0sjDEQkG8bAs203iS7w="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1848"), Value: &LeafData{LeafInput: []byte("v1375")}}, Result: "loViRxgbkWxgM9cQUsn7D1XZXHq88cL8aiXdPu9iWZo="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8394"), Value: &LeafData{LeafInput: []byte("v2629")}}, Result: "RAKONkjXVOAPodWoYQUVfY+yq7k8wUEoQsZvuA9P+Ew="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1693"), Value: &LeafData{LeafInput: []byte("v9162")}}, Result: "KY5Q8vMJ3wxVYGxnRez1II4bIlO9Op3iYeI75+gH5x8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7958"), Value: &LeafData{LeafInput: []byte("v2323")}}, Result: "ygszINkXg66K/ysB65YEVLCRqb8g3Hr8gRfv1dCgUwM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9230"), Value: &LeafData{LeafInput: []byte("v6308")}}, Result: "cGQkzkQdWrUm3z7fXoAMp1ENbilm3nXh14boGiueXYI="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7937"), Value: &LeafData{LeafInput: []byte("v8924")}}, Result: "PG0+95epQzTl4hXhNG00B12UWDf/eHGQVkkKtCgpRG0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9998"), Value: &LeafData{LeafInput: []byte("v2199")}}, Result: "VQyKFLI9wAMfjjk5v3nLx/Zn/NsrKgMSSNkQxPoaBIg="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9099"), Value: &LeafData{LeafInput: []byte("v8697")}}, Result: "muOqEvFIO5Eb3TpnX5Z6Wj+ENKeJwPcPLmtCFDgodbA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8265"), Value: &LeafData{LeafInput: []byte("v5822")}}, Result: "G8twuR9gOyI0HO9ONA+AmOIV23IdGHPY91TKkE4Tw6s="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2344"), Value: &LeafData{LeafInput: []byte("v1246")}}, Result: "XZnv72NE/4U8OM4EIJr2WcCNO72ZaRLqLAG8jGw2zgM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4054"), Value: &LeafData{LeafInput: []byte("v3254")}}, Result: "vds8OMmPgGmn9Ce9dExh7MNCyXcgubAfpZeTPSXPMhk="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2276"), Value: &LeafData{LeafInput: []byte("v4119")}}, Result: "XlEj59D+4yUyWXbTVEryzJTNdY6TmdvY3AKVb2C+HL0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8253"), Value: &LeafData{LeafInput: []byte("v9322")}}, Result: "Xtow+K4CtqaxxMJG9bSCUD0kRYmTm4lV1YSY54P7BeE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7972"), Value: &LeafData{LeafInput: []byte("v2382")}}, Result: "mj96zXkHeT/bPIAKv+ogsQiX6VW1byuP5nKr3pdzGEA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k133"), Value: &LeafData{LeafInput: []byte("v2831")}}, Result: "1uYVX9yWqvbheoRX2TYF5ZkYxYJ22RM1EemEIbKl8WM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8421"), Value: &LeafData{LeafInput: []byte("v7837")}}, Result: "IgU4hUTvT5IHR2+99WoG7VJRTW3fivbD0u0+7Clkwl4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2334"), Value: &LeafData{LeafInput: []byte("v2495")}}, Result: "WDuQt5KVTzaf7FAT6xNqM8TP3g6EAK8Aw5UxFExDw9w="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1674"), Value: &LeafData{LeafInput: []byte("v3814")}}, Result: "422i0uErB7+062JvMXRDRGNNkFogMwI5nLLnvi3A1G8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4593"), Value: &LeafData{LeafInput: []byte("v2404")}}, Result: "gxtS+17a6w2HYYlxElOsJ200QfT1hZHSiRKZODNxlq8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k3044"), Value: &LeafData{LeafInput: []byte("v7510")}}, Result: "+i0Toa1F5ew/YRlb3/nG9Tv7AWw0Qx57NqQKbPuKtq8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2368"), Value: &LeafData{LeafInput: []byte("v7479")}}, Result: "uQ0f9snmTCO9VqTMeisF7vQfXiNNSh3RqKHVgGKyfQA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7865"), Value: &LeafData{LeafInput: []byte("v6954")}}, Result: "Z8mKvmO2aYaXn+guUWeKMaPwo/YDGwEjwL4zPbhDT1o="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7214"), Value: &LeafData{LeafInput: []byte("v9429")}}, Result: "P498o3kp6Vojme+fl4crC0YEIuFSnX3U/JbYQH/cxLQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2345"), Value: &LeafData{LeafInput: []byte("v1188")}}, Result: "v4kpWvs9R2QmImoKUPhJiJ91U2lBJPbSVoxJT6IjtAY="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k7125"), Value: &LeafData{LeafInput: []byte("v1865")}}, Result: "48xu/geFRSdoPuNPq/hUUBLAAZwTDeODkCEAx62VWao="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1723"), Value: &LeafData{LeafInput: []byte("v8937")}}, Result: "gTbaXcoUFLiZ62oBLGNGhEUitsTkS29VisaXns2pDhw="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1642"), Value: &LeafData{LeafInput: []byte("v9021")}}, Result: "ihNSUwW5aHZ+EGKffLWW71/YFEnhqR4aYIhsmt2rrIo="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4247"), Value: &LeafData{LeafInput: []byte("v122")}}, Result: "rlT5Z3sq2H0Crs/gDoHhO5ntyQK/4gOme9KaOcMt3H8="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9866"), Value: &LeafData{LeafInput: []byte("v619")}}, Result: "+eoPZv975RiC7MJ0o0tc5qmRb/8WBmt6q94tRzBucGk="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2367"), Value: &LeafData{LeafInput: []byte("v7710")}}, Result: "ZlB9I5SjFlJGYazGK7UCfvVrXMs8iCPBwYx3YNC5+NM="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8364"), Value: &LeafData{LeafInput: []byte("v5411")}}, Result: "7umby0SgJyPgOEHSuO5FZDbKaE1A2fj9tZFU1j5iZG4="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k2221"), Value: &LeafData{LeafInput: []byte("v4374")}}, Result: "+uBhy1jVzxaEgq2/PVJJ23blEQB2AkyunhDFScA3wZQ="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k63"), Value: &LeafData{LeafInput: []byte("v3918")}}, Result: "eOPk+ibLc2chFSoImzGSk3621Se7/N82lIDKp0je5x0="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k9212"), Value: &LeafData{LeafInput: []byte("v5436")}}, Result: "ShigGl7FoWjvq8BiBriPlYxdxAC0VYoWPYrryxmsbBg="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k8626"), Value: &LeafData{LeafInput: []byte("v8229")}}, Result: "2C1lTlfJvvloqBj/JAKhzw22d97Wuzbuwvh1cQxw6hE="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k4295"), Value: &LeafData{LeafInput: []byte("v5967")}}, Result: "s0jS67hMsNQF6Vscc35AzkWYbHuBnSdqZGesm+wJNeA="},
		&mutRes{Mutation: &MapMutation{Action: "set", Key: []byte("k1769"), Value: &LeafData{LeafInput: []byte("v7290")}}, Result: "uJYY9CTfVUGShjHWhRIgLGfXbq71G7RPPdicuieIurU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1484")}, Result: "msjbO6Miw13puCWxbpB5B93zx5EBeN2hruaIYQnqO90="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1897")}, Result: "3kbwBVnP05oZOBVXv82x7+Yh89qf7QhA6CVZrUH9HHc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k63")}, Result: "menFJ09bWn+XDynqv5/REdCJuQL24hYnnhA9XVvhuxk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9409")}, Result: "p69Y4InapWUglOWd+lrd/smIKE09yhq1+G0c4cy6aOU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k151")}, Result: "gRB0sepTMO/arx7uOljn1O+gZ5vNJMmkvXAkWSjH7d8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8084")}, Result: "lcA0soz2TxXmxN6zFrJNgv7JlpFdalXWKjwYOAx+zFQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9212")}, Result: "kYQEl0XUequiYkrqCttFF78fp6nt+EMXIn8666kewaU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5537")}, Result: "bhNAgsppo9tSmIrq5R40Q4qt7iQ2DnlyAllVvax92yU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6971")}, Result: "V55jAhLfoZG8nPLGIs/lB0cYWrIKwzc2zbM1Tew5Ab4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7012")}, Result: "KJk28ughAdKNs+K7JGuNNgFTSIXZBHOrVYTFKdpWB54="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5987")}, Result: "HEsTu1kLBThVrmege9bGnAfpKmbZ0EALD5ePfc4CD+4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1729")}, Result: "UswumlzjQnf0vtucqopFlleYClJJmF4xdA6yzcaZhlQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8244")}, Result: "xxx1kAXvGc9uXjlzkef4bqIKRxHvP444OPg+z7+hWHQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1411")}, Result: "HUEkYXHWbGH++Ign9tBLBl2lhAgKmS7odubdhXARSu8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3516")}, Result: "kBK6kC9fhEzHZEZFRTe2zjeIoevP79Ic1aCvNL7oKj4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1154")}, Result: "ZUnqWNuREenHFNIUYHv8rv0kMtZNpsOP/zuITJHxIE0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8184")}, Result: "CF+60T7El70mClJAg01dHe62h0LBKt1QdBH7TwsQlC4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8995")}, Result: "lm1jLK560eXO5AuepRA4kZPEic8FILp87oEndMS3BXU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k290")}, Result: "zONpEeSul0pTk2R5pyDbYw5b4Nx/LhE+sxaFazLrOnQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4353")}, Result: "RHYEGQkBk/0j2o7Z1yKWukotw/XCZbO7UK8gR7e3xuo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1067")}, Result: "+7gCU3pTviWG0PugifpOwMaDoP4MEfZ9XY+tz/DKw1M="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8638")}, Result: "bZyBqhIaqMXP+6aUPjW4tgJSeHfWHZHKPecXJ8GxNhY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4830")}, Result: "qp3oMaNFoHFRKIYkovBhS1RnGI6k5SRTNFhHW1bZpk0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8253")}, Result: "4JiYg9+kINqMYmCbmKoA1imSGD4FKWFx80fpku11J4k="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9837")}, Result: "JB8uQ9Ib3b50hpeYgH5RkYSfPs41g8/4mgu4Hh05kgw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3042")}, Result: "I5foqboXJd+GS1XOO/JL9UHDExtz1zl+AaBrBPcS3JM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2101")}, Result: "1zU8tknhYZDR4SPU9miPiwGV9Fhzn8BGw66VmIbL3mo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6368")}, Result: "KJ2Qs07JIBxaWAxF5ILk4YfyhQu/30xFSoGwSBW1Tss="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7961")}, Result: "wIo76yh1WZmzoNv6e6v00KIBuk+Q94uSqpGQQ540jok="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4311")}, Result: "v/cfdwWfKKvv5H9SEKPCWzu48isjzvsGeT1bWwgfvlE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6969")}, Result: "cKiISx9Y0voiKcrAGcLpTHeq9RIBf2+dH+lCAORZ338="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9316")}, Result: "RLF/gEAiM9U7R+gz/H8En1rpaBiJ17YvvEhCW8KdI04="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k974")}, Result: "yPDkak1JpwqluwvkOi+OeZe9aEEAaaWoT4a8Kb8ugac="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7509")}, Result: "h/s+SkCshhi8DciEWM19AT7ZpU9syztGOBkohqO8jf0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1856")}, Result: "skJBgqu6G+KN9OsvitdrpT5jqfGVVHc/3ft/8T1PPj4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2353")}, Result: "mOdsA24JJ89vb+W9sdfF4Lt0hH2uTHD0cDjbIpFTdDg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k225")}, Result: "tKMEt792Nr3WTSwFV1sWYzUkRKe4OckGDtV5MRHH4BU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k812")}, Result: "+GDyJdTBodmSdZ6zFLm4vsYkzML6VolUoIPqlsW8uUA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1177")}, Result: "SXxCAJgkvQ5Q+OQ1ykfaKkNHkIL0Ce0pgx6h7fO+R60="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4054")}, Result: "2qXQqju/h+TsMt6crFvQZbSWfGSDXBDU7TKbEtQ2YKk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3051")}, Result: "V1NCOipcjm+l6ZhFlEirxau90wxaPtj3bjBt0BW0sbk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3031")}, Result: "ZRu9vnBfpOFQFb5jE9ppw4Q1jOXKZX1CNMz7/N1BNkw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2229")}, Result: "8izAi8yRkwnoqwP7NG9SSr9nInfojm6gy5hPuMhjMbw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8015")}, Result: "xUwQjxn7KyM8W+j5fgZ/owDP4uU24dlHFVHmAqRlqB0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2344")}, Result: "Z48JmvYRAkAqLw3LfyPk6jD1ZB7s0V7xmyhcIJFn8Mw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8971")}, Result: "CibZjwQ5EkfcpJg4cGkGU1/4gI0Oz12n/KDCDEX/5Xc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5432")}, Result: "MxWzZ+R+iCjUqA5LuKxsiiASZBkvBglUhBh3l/4FaHA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8375")}, Result: "XfrHFh63Gr3Qa9WlbD/lwbv92dmPfmAPY4sTpCQ4kNQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3336")}, Result: "L1SYkbCMlewBj93FlECM5KtI8K7b2ec+QRuWEKUou2k="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3796")}, Result: "Z/Rwb5k9vwjW/tOPv7YdQsjZ0sHDWASDLsS4DpLTPbE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2182")}, Result: "hjWCdRssviG31Gw4WzrN1ZiGkyiqd8buU/koUewTzdQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k122")}, Result: "SZgWGolpD4n7V8Q8Vph76rt+f2sZ1GeN/ncVXvTgPGY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6894")}, Result: "aYGy1+1cLLYey2QEgb8EaZh6Pm9p/5u6IRs3Gc/htJw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6434")}, Result: "slt+wH0iCr3Bsj4G3y+pWDOqb/5CSHGVJdRN+y0tX5g="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8906")}, Result: "bXiFQo8pHVXIV/sdm7XQdLZln44O81HSP/R4yD7C6xA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4139")}, Result: "AHcRHGALz5pYnU1zPkST03C5A8f2STV32qur9Lc7W90="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1189")}, Result: "oPQ2GezL4p7nemf9hpGsy20DP1wpCqI0FCC1I5lLDJ4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6005")}, Result: "o2I49nZJnn6z6F+dCyET1ot2G5YqPiSaXyY3P/ZOGio="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7356")}, Result: "pyZbth6ZKqGGlJAZHHGZ5fvt2WQyuR2vTK5UNUoPKOM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7989")}, Result: "BJ4uW54zaVspWT5HHUSn2qNvcl5DkW9hR8cd7PTo95w="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2940")}, Result: "DajPUx5d/OHkc82JKt4wfdPnS3MY7KIj+CVqEbAevRI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7280")}, Result: "4/CHZnzZOAENlyjFKg92MkjCjhXHPTdJmtYBdPw0RHQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1828")}, Result: "U6SCk/6OC9L5auRhEWIHigk4N0ucM7nj3euwJdxEwYE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2124")}, Result: "EyW7w92L0GbsbAmy8aGmnJ5CHu0ZU7SRd6Yo5N5IEOI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k133")}, Result: "Kpjm3obZwQ+IBlcQpe+OWgpaDrKrO7k5oQbGSQCFxpM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1509")}, Result: "KHBXdyHXbisHmr0sSJtCjlCA711WmqHqgqQEGisV4yc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3043")}, Result: "aysKRU2Nzz9+RUT5i6VNej6qbvl/aTHEaNvvHwufnvg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3334")}, Result: "kBv0zlGFjK1FbgK+loyhnIktsILetjI9uaylnqMba74="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8473")}, Result: "TM3GTwHtefdpHCLuq9mW+rD1a30GJDFvnIFlv8M5W7Y="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1482")}, Result: "bCBVi26faZzNXQUVOiL0Pb6FqvpQU2P6Zs5q4u13Sd8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9025")}, Result: "OmiisMgfZxGjR0Q0JsTNnE+oCAbxFyi+VwD6VWRIrgo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4593")}, Result: "8HR+xkuDF61gBOzPQnfTSTicLklp3oysAmD9HKwQKvU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5906")}, Result: "GfPJMT9eQx+JxEyntqvOZPjen+3gWclJ88qaGWorMeU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7865")}, Result: "cramJ7ng/lBj+wAt7nU+dw88uId6Sc+TAPtqxtGx6fk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9473")}, Result: "hYBLm2DK/KX3jG1sfm3nDwn9XH0ZB3RAK6wtcBr3TVk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5438")}, Result: "bqQpYi3LXUqOq9S8C5VTOfCE9FRMP/Vw5cpPGH+84NU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6998")}, Result: "21Ad+hqIBgCW+HhCD9BEOvmt+cI9CLAAHhr+/2OKkIk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2368")}, Result: "xsosVfjkZmCbOr1mOWMnHSK+88wUuZSl65B8O9l9sVo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2402")}, Result: "kexTBa5YJft2qwww6oTnb1+tvC/5FR/6iTc9J+nu4fM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5778")}, Result: "YhH2MsxPXcwOgn8267Qt+CUfeD4gvvO8i7HefHzhD88="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3343")}, Result: "bDlxBcvls6pBxehWEt0k8lik53xTO+u2lPMq85SjtiE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1833")}, Result: "UJzNZ3rvVTYqQKSlHoTheYbIO8b95HTTEDdb41NRy5o="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6065")}, Result: "oaDpTq3wMFAub+iPGS8tiTos5YN06/cELTGfbSPXOOU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6696")}, Result: "GHMnYvyxzQgz1XSmjbCWMn9BO0i8fS8pM3+uqa2bMEY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3966")}, Result: "3m42ipJMmQossjjyIMcn9dGlmcgnA6ESQBk44RCqca8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4754")}, Result: "5dX/Ym3kja+WZOMhBAlJFXxH/n3NQZoMAnJ6fj4S6bw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k306")}, Result: "m5uxf8oDiWjMmdv182W9H6n5r2254RoXLIQZa52DtrM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6201")}, Result: "EvmUVePcgGjW0Fu3SptZ+XOCl/KWmRn0AqYU4ulj70Q="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4751")}, Result: "4+uZkmJrkb8pOlzWLJdfeirPp8ObtpwG+f4BPlpjBd8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5276")}, Result: "iLhDwS4r5bSrOcmROqZHb27iWkOIpS4Ar/PodbmlYXM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3419")}, Result: "Y2Gob/NwqPtWrqBGDOFku5YqTFH5kbAIAJI9Wh28bUI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9850")}, Result: "VkIyzCyobu+kWSRBOBKmXaDSXp7PQ4wh6aJUvDD64nk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1972")}, Result: "rwix3GzfSr86mE38PEHyhYT0rivFOWBC7wmzFpWelTg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2993")}, Result: "BbOl0fR51AnNfmfTcP2oBVcSDukua0n66eBkZfeqvjQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8235")}, Result: "/K3eIwUjajkLb+YUTsIYMA+FB1E40Y2aA9963m+mJi8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3769")}, Result: "KIC6tdgyMmzN7Wa9z1JSS0kF1malsps2FY9QFdzYdTs="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7223")}, Result: "nlkHGKsG+8/YoaQV+X9nTfUJepb/QbsOgFyydrdk6P4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3365")}, Result: "THC9C6CP4eLXRQ1mkmKnk84PXhNkrQoCq3PeYB/eig8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k807")}, Result: "FDSYtKBJC/zml4FQpfF9OYOMUrC6qpEi/wt/Mst3QSE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5719")}, Result: "ZEsKhOOFLfQU5uvoN5DNqy52u1ZKxTBj6duTA2u/x7Q="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2539")}, Result: "dS16bV+B3GTr3k1bZuwzDLTjcaHD5Q8Vv2sHMqWsbEU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3892")}, Result: "le/ITJ8aLA0+zmLJpwpOMhfTGXst3bTC367nj+EdzYE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5826")}, Result: "GecHu2Mplco8HLu0EUd522mL2owffUtwhky7cqzHHTE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9230")}, Result: "2O3hSGW2X5dg3aDpZbGTf5jT/6yPTO9Due+ivS94DYk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6652")}, Result: "C5+QF4QrGTusk+c1p4RBQd6AJ3QJ2H12dGZcj1bdRDY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1642")}, Result: "Yp7q6mjKMSBZJ8byKUtp9E0/qeXQ1yL6V9ZB8qGCQNk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3280")}, Result: "cFp6nV4xfxKGJSZmGXVr+UY9Q6mcs1QGuiWIoBod2V4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4295")}, Result: "Qyl3xPw60ZHv9f++qbMfsshV5HX7FU24CTgEONhZK3M="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2357")}, Result: "Du7BwbQaAbL/ZZlav9Giv39T7M7gvKH6KyX4h/Ladp8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7267")}, Result: "zyLproTVTA2s9ze/4lQEmMbdON0WOw+ILBH300etRHw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6114")}, Result: "HRulszWNYlMekrH3oPRkL1fG2mbdid5leeOGKiYNRo8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9863")}, Result: "X9wnTtdLALl+psYdp7jbNkuQjnnKVwdsszjcIy/37eo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5940")}, Result: "xga/6Jba6WIVslh+/Fs4oQQnhRK94aUfC/YknQKybvU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1794")}, Result: "Xsqm9ukJH64Jtde8juLbgUZVQZVrLTIuqQgOd01OUTg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6239")}, Result: "ewqx8I2YvDuALl6PDmazWYG86I95f8Hw2rqV6KR/Sho="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2345")}, Result: "RAiGHafsjaMEjSZluVL7ggE50dLX0OUmtm/s5vHox6w="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k714")}, Result: "vcvWYuCrnjA3jgaqpw8bPAwtoNxI1YlNt+wB2L/Bb6k="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5958")}, Result: "dIsvbjzgsern5UDWjQanPCRKaMTWapT+SMS4yAeBJE0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k964")}, Result: "7mDAN20OoUoiWJhVYwl5bfLgjtBxz7zIUAKoL0AWkTE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8882")}, Result: "PN+Md09GgCSbMAAeTn02N6iNtj7xN/juJv6wYQkRK80="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8275")}, Result: "rALRS/ZGNp+BxVeDvWOJfNSd6G1qUIC9w2WP4iDlAn4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4178")}, Result: "zXa1ds0IPFyUxYME1IC9GRCbtSo56NX4mha8IVTSAes="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9567")}, Result: "rY7LzmdByyDt2Ai9cT6o1yaVGwnD+2sgK/q4wsRbyjg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1023")}, Result: "ViAS55jA5uH4DZo4ksXsrhKNQ9epN93NvQ8FuBHfLjk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8769")}, Result: "uEaoyQw1PyuTX3b8lqPTqYGYZXWAkeULSsSfhyGsUIs="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4629")}, Result: "nhswvbXtsPurTE4rbB4ifsUUl0HGHC0quDlg9KJ9Pp0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8818")}, Result: "JCM83wI0vulPwz6+RPOBea6HciqQ5wMr1cOx7FsCCFg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8394")}, Result: "N39QUIaqD8yCDrDCDNwSr3mUX+v74IPcmkzk44uMqqw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5188")}, Result: "oRLPV4v4EcG80PeHEPV4govQGEDfK6xVDbPvZD38PLM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8421")}, Result: "WbBMAZPlWmsp2FXkxl3HBLVwTAmhLePQpnPIVmNzNtA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3998")}, Result: "ZpatkfvDvfLxcQBtk63ffoLXV6YQXY/F8NGhmAAdk5o="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6023")}, Result: "phsIdGcjggUT/zVXvN7HZ6cpM3Qe9nJXquNf3+jn2dY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k834")}, Result: "Lsg9GPxwTOCnBCIjKxfLw7F6yagDuH9DheXrgtPf5DQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4429")}, Result: "imwRSHg5wSDLGyQiMIL2dUMwMexDM0XbZoYqjxHBf9s="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3149")}, Result: "iYR7Rzu1nDquPU1hDV7kRNCgvFYD6nIqXu4ltymvk7E="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k581")}, Result: "MxIxzBzwzAcKrnN2y0SgHcnCDRJT+qXaiGB5qO0SX24="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2221")}, Result: "VjQZL15BR9nuGn3PxhOs53e0Vhn60nLWevzgu29j0Bo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2357")}, Result: "VjQZL15BR9nuGn3PxhOs53e0Vhn60nLWevzgu29j0Bo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4704")}, Result: "4y2MejCjqBQVB8oh8VTGjo+xnYLKwYuIjZZU6jYqzuE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k802")}, Result: "LGmK+p23WV9orh8UTh4yfF4PjXHICImpsH+bWcUKADA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6196")}, Result: "9INvVwpN6uZlLc1nKKkDF215fVmiQf82IUiGPsTMQcA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1101")}, Result: "V40rf0PXqxaj73dd0LU42FQcKA0tTPCaBf00zQs0BUM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2276")}, Result: "dH/ESrs/JVQqXvctlGCL8JPph54eib075c+/SAvxHNY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1175")}, Result: "MwmntsQwbyrrWy9m+nnIPrroHUXvYKL5kWcTiMUUePU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1610")}, Result: "/Vnq/GC3IxSJEleOzUIBEsLWZ8xIgY+YQHAkB9W9wA4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k483")}, Result: "Tx0wWgAs5osOSQ4d0VoR+TkgCph71Yg6ypocxsyFqUA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9866")}, Result: "/8DBO/UjnqIcIMPipOxrUwn057Bmq8IFJ3NvbaXdEjw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5114")}, Result: "fxZU4rPlxEe0Qy7zuf+sjk1b0iVzKeXrDIbI7cjLp5o="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7274")}, Result: "ssMkhGDNgV4RHvO+Ua6uzQqZsEAXBg/EA+MgfW3Uas4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7097")}, Result: "HEOPlulF4qzerob3RFc7mSlGk7JwrVmQZppwyXDwvr8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4908")}, Result: "LA78RSKArwe+9zvi/09T2sA/MTEL8ruuF+01cnmCVU4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9536")}, Result: "gwDHaZCfPE0paNJXKfkr4kVlZzpsKEIdz7It7hRsKf0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3274")}, Result: "Kc6SpiS69bODkJQF3MljNHq/5UW/9yCPjgvFZKcPO80="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1848")}, Result: "WFSR4XVOPKakYvybXLO9+0EjJvzSQVjPt81XIlMnOvg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4142")}, Result: "fye1aOvTivihf01riXGMtjFzkLXE4VbRODNGV+DS7yc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4788")}, Result: "SlZFVpdTEnjpn5cSFAsw9kLKhUiX5a3p0Xs+WLb7+D4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9099")}, Result: "0b6fuYxIb56wUa95LkwvwRrXPUr/dY/qVUz1piDsf70="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8435")}, Result: "p5e/du1c2dkM3VXXTuKnwOu6+0/Z8eA0lqnP7IDC2fE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2334")}, Result: "CKQF7Tu+VGq3kJBW27/QWCxU8U13nMd6VsOOAOxdNsc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3013")}, Result: "trOJt0tZT6T24Jp6yHFpxDms8YIaf7/DGELG1HwS/YI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4380")}, Result: "hdqIaNPClaOnfgH3uLG0hpfnv/k2B41J3BezPSch8nI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6075")}, Result: "iTvCpPBKCQs7iXisfp/P5O2fuouoZmh2wSzT3nu6QQw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k46")}, Result: "0Y84k+IPk7YjugCkoRRm4vpSZDUabae37nabxJqlp1c="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3208")}, Result: "nFLtmAtxNdFjaXug1HSeDxBbiY3c9C5WTdZtxfD90cw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k46")}, Result: "nFLtmAtxNdFjaXug1HSeDxBbiY3c9C5WTdZtxfD90cw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4088")}, Result: "hfHIE+dyp5dmLgLmNSm2lPFG0OcVmZHzrnO7B6gYQm0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1833")}, Result: "hfHIE+dyp5dmLgLmNSm2lPFG0OcVmZHzrnO7B6gYQm0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8626")}, Result: "Yvy6oFN5H+eIageJwBSTInff94/j6t1GAWPvtf4o8EI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7905")}, Result: "Hl0JBE+esacGpaxHR4p3ssuNBw+vfhpQDFOivAH/fC8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2977")}, Result: "6ye7OS5eEF+WtlsXDU1n4lMCVN74doj33kBwJjSrDf4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8321")}, Result: "/D7L/N80VMmwK2FQcOaGt1EMi9tD5hHFu/TclI6rAko="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5141")}, Result: "OpsIVNgKYmUvaXMvkRyXStvXRAOj4qNYR1WyK8LMadY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k63")}, Result: "OpsIVNgKYmUvaXMvkRyXStvXRAOj4qNYR1WyK8LMadY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3464")}, Result: "vFN8hlwuOZkf9JoiWlaBHgwnm6KNyfxL4Wdl6D1d/bs="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k862")}, Result: "qDXGHoW3fv02fWDtEa6lW+pxHk/Q5/8aPuKDp2/iLr8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7217")}, Result: "kxF1J4ujn1eqocpWzYVcPv+7OZcL7e605p2/tvdnrqM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8405")}, Result: "PyJyDdP427b4KwqtUb0k+355h89QcJvWHJsV4595JBk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7168")}, Result: "WnKavicy5tz7uxU+BTGE/4GUiQfb17wasI4XeBuYFWI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4237")}, Result: "1Xk7cQ0ihHru8V73ZG3ApvnvaAnYI+TXmTSBWDMxsTE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2036")}, Result: "Qf6TW2fi49CSrhWvZ0FftgOD4gpHWrHb4KnpebSLiyc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9429")}, Result: "UDdrAIGKGagJbGCMJkO7vNOPprz+Yl2k03quIaoIRTQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9973")}, Result: "sSJJK+OrSqvI31UL2/woHtQyNF6ZCVMwvwjyOwR3bhk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8265")}, Result: "zYuOCSgECw8jHe2YEHpC40ZLAiMGYbLmoe5Ri3RZrEw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5594")}, Result: "4/BkvNaG6grVuoNrq6IY8TrZLp6A2ELSO6InZQsoPRA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5049")}, Result: "PYuqbiGo4FaHD9xuvGYot86756hrMmqGxTW+0wvdjSo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3787")}, Result: "h66v/Oq7gelAZKIqIHepJbekQfQtx3CDZX9Kd8sXdjQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4874")}, Result: "q1Xgd8YYf9nOP1bQ6OUxG9Vdyd8y3S2pqhb9+nJ1JqY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2366")}, Result: "JpfxXX04HPFKzhPk658iJ7A/L/IoDggFgZY3r4HgpqM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4500")}, Result: "7C4RG0h6kuitMR0EV66LoyObVWPX/kGae5lXTfOTcck="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9669")}, Result: "kwxFYILj9ynfNjZ/eDqAeXvzQ669IVh+yk/Zm8dV8JM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9601")}, Result: "nNoSBXCemFUu9o35t/jOOoJ//K9Skw4scDB5Xs0pSXc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8126")}, Result: "4ISGafhZ6ej2T49NYDxsRVW7to2ub61Xdq/7uQMXC3Y="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7299")}, Result: "uz09Iw01C1Xynm8A4NLmQXDRvdq5XkURmnzHfo113+o="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3512")}, Result: "I6GToyZGPJY5Nlrq6VeXa3ozpQX8v6/DqiHjf7lPYn4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5172")}, Result: "2WygEaWUqtVEbA0BeFrZRu230H92nsZoWjQp7GN3lVI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9544")}, Result: "Lq76cJ+WlpW9RfIaKgFnYuvBYIq8wKNlvlrARMztSAs="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5917")}, Result: "QTSyfv+2HliduG6ILzFlKYEHW+WivbBG3lp66gABNuk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2375")}, Result: "UOJFniQdhza3IOvsQTv2jz1CrGOlh8Cel9IxZvYpr1A="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k252")}, Result: "TExXuaWY8ZcBzp5eKwGVyqqtJCTHwevWWLv5isnkA9A="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3412")}, Result: "0KX4C4pPwDo98gHTpNlL3zO6DZSJ+Ss8n5OixtSOuaY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k510")}, Result: "oQPc9Vqf5NTrr/Dn6rHVHXhe1guevt0yQl2f4qJtGF0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1661")}, Result: "c904oElWVY+90Ns4uMn88SAgcq77w3pLgelxElG17ls="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2367")}, Result: "IyOOSd+YNggDmOGfOlP2F9eoaF1nb9uQDIlCgPDS3Us="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9160")}, Result: "jFCA0txo8MlvoBnOuJSYrBSPPRFT4SRhcqOxrbLhxQM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k775")}, Result: "vo2kQWX9t36UWeI762OoBFpnxlf04O6LvjbcQTb6Huo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8279")}, Result: "Ni9yJaWtKihcd/W7CdtLhLWDzzbq8p0Qk+YKnouYrrY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6069")}, Result: "Kg36h/IjZgDquANtRPCfS6Yjnjg4miAntQPPjVJtAfo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k753")}, Result: "BiHIxlGIuFbhej2VV13pe9TUbjUCoFsl2bOUF/FCQgo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1179")}, Result: "OW1rlxhpppo/zAk9XK//uvAIRy50+HRlQoKeJUg32Uw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1810")}, Result: "WFLtH/Awo98Ld3IgUfVsfExcAf5hdDmF8rSOSsa4D2k="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7937")}, Result: "9ra/eS6JdMPk06dL0q2CQBag5m86wFbV/r69IurMIdc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9128")}, Result: "WGfXeqsDdyEbVnINNHs/v4c74bMISJA1yYUfhwqjHIM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3182")}, Result: "mdFrTkV7mSzEkJkGLisMiMjSjLHjqwKvTbYwY5UnsB0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4689")}, Result: "5AvWuvZh8zoIl29WhstGNfr2XWefjItGM+Ye6toTUnM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k195")}, Result: "Q1CYmmpHH2n3AyaVga7h5whzdU0P2Fy+4mxZh5DC0IA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8598")}, Result: "laeCoyPi8PGB4CJYhojlZMCs4AqN+drJ5VwSTgmkTRk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5413")}, Result: "1unbjRES/N41X2G7KxfpimBkdiSbuRP33Y1enn7zeu0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6966")}, Result: "+OmyaOg4YBN9q/j7/0c8uAO2a4vdAofZbyPJEMnaxZg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4247")}, Result: "pC8uJHIpVBWJu3u7LJAyEM+KtdZzGPIuYu02QzPvxSw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2443")}, Result: "U1Mwl8J4DLjAdcvOsHBTXidmKNsqNbNqGjDDMVq4uWI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7958")}, Result: "r52PATX44W2YmlSvlC178/phjxVw+3S3WQoKYdGvelg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5974")}, Result: "abL4YoxELEvG8roWmrUZIkS9Nd+HEp0Caqt+LGHMCTQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9676")}, Result: "s83B458nV7vFTrAt3cRUPVbhmu5Y+R50kUseBdtEuY0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9186")}, Result: "o8hV5IHPzHgwUcbsJVl1E0vLxLH54r7x0Vfz/ro+Mus="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9695")}, Result: "eoAWw0ouve3iCb3vMKTm3LyaPVtWYQuJTxqEgKNuNe8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2171")}, Result: "Yo+N5XtYm/MbXyf1uOOsvG4XKEJnrM7kTFO+3n1tlpo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2247")}, Result: "6fAcJAjo92hVYpTrunmRCelgm7/x4KdTuWVrccqYuxE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1725")}, Result: "P9MG+LyqUdmxePR/XliJiREpCFd8im4539X1MIpoJvw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1491")}, Result: "Gj1cawcQ0XDNEjLt9HmPTYScv6bMrkdBJ3sgwqea+V8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3839")}, Result: "7BXKPAJTAN2jbLWrmfgxBAN3sfMSCBkOM77HvytsOLc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1737")}, Result: "W8e8z2ldof6qcvDUsqf3dfdwCl/uzcBmglUs+WPNRuc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9730")}, Result: "4Bv/Yj7lAJnsrnBJ8dRaD4U9KkLv1/2qIpd6os+gWRo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k294")}, Result: "26yDru65YUWYNzftz1MpNByPAtQckNbPyUHruHu2CxI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7214")}, Result: "sO7xkh/v82MuFHPmHE4INN3Zd4SbvoZRKlpps4jpigs="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6297")}, Result: "ev1UpCexUsQUx58npkAsaTBJWLmvJ9W3SwsrHxoh0bQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4241")}, Result: "j28rhC5zmugnJIyEJgg/kZWeVbFEC99nTYlrv5+cgOE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7201")}, Result: "klwatek/c5pm1j5EY2bdBWSlAM16CA5P8qMtJdQJ3Cc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4747")}, Result: "ibCKi3kp/BHnGpHvZTPfbYK8pgb8oDnX55p3L7gGhyI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6304")}, Result: "IAXMk6dRXksAZrtJzNK2PSCpJF5k3ciE9b6NhyUYJ/U="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4441")}, Result: "U6GbN1Dv4zqjd7ZOZldTGBlCSDElxwnWcFqG5Om36so="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("blah")}, Result: "U6GbN1Dv4zqjd7ZOZldTGBlCSDElxwnWcFqG5Om36so="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4933")}, Result: "Nm60ts5WZLor0BtaQscHpVA4BdonE4bP9jtfo84QT3Q="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8581")}, Result: "A0VO4UZx81lXaqlWGIFISTjAzvWxb/K/OHz+aXAVCVE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8364")}, Result: "iBdrRS+JMeo4CHPgQDttaz1evFug5kQetbKT3rYBLiA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9998")}, Result: "PwNKPSASRfm4CLMyWuasoOA+6keE5o9SIOFEFBR0tvg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1693")}, Result: "QVKEpl8oRovnjI2jbWxqgs28cPqp0CprlvRDKGrGdHI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("hahahah")}, Result: "QVKEpl8oRovnjI2jbWxqgs28cPqp0CprlvRDKGrGdHI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8708")}, Result: "EwQVYSSUl553WHsM4zUVNd2mZ5A2Bfa27Li1wqeDPAs="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4205")}, Result: "jbZmajxKoBPKZKWEPRvrsAvXgwzQOtysAQj18jVwnTI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2026")}, Result: "df/Bth/XN5PLTU9Uktkfikhwx3t5JzS4G9IcGRjzglE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3264")}, Result: "RbUgUadQiCCBt5+9i0/ccXy1HvSyySli0kYGxstpluI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5923")}, Result: "4npFJ2mAtEUrJF/5KRTBT76bWA6ewhL7YPAZ2+/0sWI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3044")}, Result: "wF5kyFZ0nacLZPjcziK3Szxqv9TacQK3opHwahFjZ4g="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8091")}, Result: "IJRiZRtIfyGQDVGNo4KlVvz3i2iKrEPIvLb0znHHxaE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3657")}, Result: "AT2+D4oK/XPxBABEruhXas1rZhrcDYfpOjYnnOSM7q8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8923")}, Result: "btvqQAKOsEvAaS3D5zyyFjCLUTGHXJjR7l9ht9fpl8s="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8077")}, Result: "ETBXvnxjbL474rWBBsQtzjcdnn8VFcyTNSQY34SmwaE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6676")}, Result: "7HTP8k/ImCPkmH4yqULj+ggSdY/Q5wKGbOTRh7Msnws="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k645")}, Result: "YzyBw3sJXtCcqim3wyQsauBzy7hYJlSZxuWK6uulfec="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9059")}, Result: "Dhyi0RcYioXyExtMZmOr6OJKMwRJc7iIPpdijAaVbJU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1000")}, Result: "HVVNzf+A0iPEnPBn0WOuUnjp9Cjz8tgtuRN0G20nLvo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8202")}, Result: "zgROqEM3zi5hIpgusmtb02E3bCfWXx67/FOrxq35bho="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7907")}, Result: "j1gVm92eMehUfxgGmC56GyTNilYAtdTmK85eP+cCfUk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1424")}, Result: "29aYkuk1Zdq2Ch/XEFq54O5z5OwfRiOKlHeUbNnSDo0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3061")}, Result: "qRJk1W3nbhu6Rs3PYrF6WA3SHlhmfpqHDZSuvB442qw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7125")}, Result: "LtDjhsv8d/1fkWQR8VggWRyITeVCj6J4F/Hk3UHggT4="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4194")}, Result: "VZAzQkwpVGRkdO5GeDDLQYM8voc23fntGNI9lvnDb4s="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7996")}, Result: "mnaag3wlFnP7foPo5AWieZjzMBrFr5db7M16rTTiE4k="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k251")}, Result: "gu5y5EbJihbqJA2Qpb3n5wZSQGSkCZvJ8IvNElZ8BFk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3448")}, Result: "RNObOseKHt8qIGpFG7/8UWJ9tnIdGGoaQySBFHOBiBU="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7949")}, Result: "GnmctlGkmlB9fjHaXCPfgId6K82WltKRSRfqMu4lhNI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9952")}, Result: "NoUqDn+rlFo2TFAr4TAuKSspxfmMLFJ8OiRemozsU1s="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k205")}, Result: "7NLAxWc1XV7Xjfz6r0hM+7eLnUcQu+mTbOo8j9NdiL8="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6241")}, Result: "u6p6adxj1H0HVbusA5xX4YNskNsEAQk5qXIUrABxRpM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k463")}, Result: "G8HBQahjnoxPg57C17hdJHpqrlXWT+mhlD2TAtP/nYw="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1769")}, Result: "StD85keEbPobMCrlKyWcHRfRULBnqM083YqmThQBh4g="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9351")}, Result: "Tkxw2oUJ72X3MDUrFhBBXHAYQCQ3FbvteR7M00n+bgg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7255")}, Result: "AgbPYSlWvNQd2GV+vIRbhdJh41F7kpm4jtqfTWz1IZk="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8042")}, Result: "AwBdhC9LgZn4lwXogGgrIisIiCgUw0nDbtbxdELtM+Q="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6092")}, Result: "a+4nauex+PcMzSr0EiJlRYouJO+391w/d9b3jYd4ecA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1723")}, Result: "nLcxI3GDwD27H051ktyV1FcpiB363bDzkptNPzqXoKQ="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k735")}, Result: "yOETHhVhWtTQhK4uHg/n5KFREs8cb18LaDS/prt9qsY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3527")}, Result: "CjaKAoHX+NjHH3XE+XDD4KvnO/OUZDBBVKECan9IZZs="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k989")}, Result: "UW27ydXQ+FJs1CE40XMvwcUFwK7ygG1QpCLh4giAxfs="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9899")}, Result: "tRHazM/MkZq16ujrMuDjduBNxo36jH4glpTe2hq00Vc="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k568")}, Result: "FFRKoTJpwteOx53P/R/VM8kBAD24YeMk0GbYexh5GDA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k5097")}, Result: "43xz7h8FpuIvLCxhyNXYluQAeW52IlaP4OOrOlJ1HJE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k8899")}, Result: "hKx+Es8nX+1UqSP1ASsigOBjCpcJzC8FiFOUtXPXX/o="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2190")}, Result: "YJC/XSniVibjTbUCvdQ8Gr+sJnpqskRAXS6X3Kqrg4A="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k3902")}, Result: "sRdxUf4XehZZSSoWkd1GKpH0CSXae7gFbQz/KycLKes="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1436")}, Result: "R548g6plnDQEpbf+bXXhkwuz6CFfkbRA7H8faMvD7UI="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9615")}, Result: "9SOONG2rG8am9PUx0qkOVisxZOeX5SdZ2ASa0PwQWXE="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k4855")}, Result: "a6GWtbWZr4YAj62gQFpx6JiwTFvx5XTbvop9ri61yBM="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k296")}, Result: "NLQiy8cCVSPcegYh0ttteuy0LLcIyqdCQVcdBy/3gq0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6117")}, Result: "Kw9O1dbbmJifI0Tz5rwR4a86PlMlpBXZQzKQvMgTiBY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k6925")}, Result: "HoAWrDZJoAwAu19RUbW1DpY7Ox7+rmXiN5pNghUJhhY="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1674")}, Result: "Y9FAeoRsjYOPZJLRA6WUjrKCFdJ9d3HPl9fjDtyaoR0="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k9706")}, Result: "VO/lacUJV8Jb9bIbBxwyssy9+vVzUlLv0Cx8v3FL2qo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k2703")}, Result: "Gqvww0ODJLPuoEHluiN/PgIo2uXdhXhJmi+33WzI6Ac="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7972")}, Result: "RNg6jW1Px+2Yv75jISyAc+rgeM8EI8QJ8ZB5aLP9LjA="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k1577")}, Result: "xTYFntMDGvR5HQ2wCq18ho7oHo1vSe4HBlAXZKUbudg="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("k7914")}, Result: "xmifEIEqCYCXbZUz2Dh1KCFmFZVn7DUVVxbBQTr1PWo="},
		&mutRes{Mutation: &MapMutation{Action: "delete", Key: []byte("bloop")}, Result: "xmifEIEqCYCXbZUz2Dh1KCFmFZVn7DUVVxbBQTr1PWo="},
		&mutRes{Mutation: &MapMutation{Action: "update", Key: []byte("bloop")}, Result: "xmifEIEqCYCXbZUz2Dh1KCFmFZVn7DUVVxbBQTr1PWo="},
		&mutRes{Mutation: &MapMutation{Action: "update", Key: []byte("bloop"), PreviousLeafHash: []byte{}}, Result: "xmifEIEqCYCXbZUz2Dh1KCFmFZVn7DUVVxbBQTr1PWo="},
	}, nil)
}
