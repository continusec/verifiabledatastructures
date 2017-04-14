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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/continusec/verifiabledatastructures/pb"

	"golang.org/x/net/context"
)

type HTTPRESTClient struct {
	BaseUrl string

	// The client to use for sending requests.
	HttpClient *http.Client
}

func (self *HTTPRESTClient) makeLogRequest(log *pb.LogRef, method, path string, data []byte, headers [][2]string) ([]byte, http.Header, error) {
	prefix := ""
	switch log.LogType {
	case pb.LogType_STRUCT_TYPE_LOG:
		prefix = fmt.Sprintf("/account/%s/log/%s", log.Account.Id, log.Name)
	case pb.LogType_STRUCT_TYPE_MUTATION_LOG:
		prefix = fmt.Sprintf("/account/%s/map/%s/log/mutation", log.Account.Id, log.Name)
	case pb.LogType_STRUCT_TYPE_TREEHEAD_LOG:
		prefix = fmt.Sprintf("/account/%s/map/%s/log/treehead", log.Account.Id, log.Name)
	default:
		return nil, nil, ErrInternalError
	}
	return self.makeRequest(log.Account, method, prefix+path, data, headers)
}

func (self *HTTPRESTClient) makeMapRequest(vmap *pb.MapRef, method, path string, data []byte, headers [][2]string) ([]byte, http.Header, error) {
	return self.makeRequest(vmap.Account, method, fmt.Sprintf("/account/%s/map/%s", vmap.Account.Id, vmap.Name)+path, data, headers)
}

// Intended for internal use, MakeRequest makes an HTTP request and converts the error
// code to those appropriate for the rest of the library.
func (self *HTTPRESTClient) makeRequest(account *pb.AccountRef, method, path string, data []byte, headers [][2]string) ([]byte, http.Header, error) {
	req, err := http.NewRequest(method, self.BaseUrl+path, bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	if account.ApiKey != "" {
		req.Header.Set("Authorization", account.ApiKey)
	}
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}

	httpC := self.HttpClient
	if httpC == nil {
		httpC = http.DefaultClient
	}

	resp, err := httpC.Do(req)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	switch resp.StatusCode {
	case 200:
		return contents, resp.Header, nil
	case 403:
		return nil, nil, ErrNotAuthorized
	case 400:
		return nil, nil, ErrInvalidRange
	case 404:
		return nil, nil, ErrNotFound
	case 409:
		return nil, nil, ErrObjectConflict
	default:
		return nil, nil, ErrInternalError
	}
}

func (self *HTTPRESTClient) LogAddEntry(ctx context.Context, req *pb.LogAddEntryRequest) (*pb.LogAddEntryResponse, error) {
	// TODO - figure out how to deal with extra data...
	contents, _, err := self.makeLogRequest(req.Log, "POST", "/entry", req.Data.LeafInput, nil)
	if err != nil {
		return nil, err
	}
	var aer JSONAddEntryResponse
	err = json.Unmarshal(contents, &aer)
	if err != nil {
		return nil, err
	}
	return &pb.LogAddEntryResponse{LeafHash: aer.Hash}, nil

}
func (self *HTTPRESTClient) LogFetchEntries(ctx context.Context, req *pb.LogFetchEntriesRequest) (*pb.LogFetchEntriesResponse, error) {
	contents, _, err := self.makeLogRequest(req.Log, "GET", fmt.Sprintf("/entries/%d-%d%s", req.First, req.Last, ""), nil, nil)
	if err != nil {
		return nil, err
	}

	var ger JSONGetEntriesResponse
	err = json.Unmarshal(contents, &ger)
	if err != nil {
		return nil, err
	}

	rv := &pb.LogFetchEntriesResponse{
		Values: make([]*pb.LeafData, len(ger.Entries)),
	}
	for i, x := range ger.Entries {
		rv.Values[i] = &pb.LeafData{
			LeafInput: x.Data,
		}
	}
	return rv, nil
}
func (self *HTTPRESTClient) LogTreeHash(ctx context.Context, req *pb.LogTreeHashRequest) (*pb.LogTreeHashResponse, error) {
	contents, _, err := self.makeLogRequest(req.Log, "GET", fmt.Sprintf("/tree/%d", req.TreeSize), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr JSONLogTreeHeadResponse
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &pb.LogTreeHashResponse{
		RootHash: cr.Hash,
		TreeSize: cr.TreeSize,
	}, nil
}
func (self *HTTPRESTClient) LogInclusionProof(ctx context.Context, req *pb.LogInclusionProofRequest) (*pb.LogInclusionProofResponse, error) {
	if len(req.MtlHash) == 0 {
		contents, _, err := self.makeLogRequest(req.Log, "GET", fmt.Sprintf("/tree/%d/inclusion/%d", req.TreeSize, req.LeafIndex), nil, nil)
		if err != nil {
			return nil, err
		}
		var cr JSONInclusionProofResponse
		err = json.Unmarshal(contents, &cr)
		if err != nil {
			return nil, err
		}
		return &pb.LogInclusionProofResponse{
			AuditPath: cr.Proof,
			LeafIndex: cr.Number,
			TreeSize:  cr.TreeSize,
		}, nil
	}
	contents, _, err := self.makeLogRequest(req.Log, "GET", fmt.Sprintf("/tree/%d/inclusion/h/%s", req.TreeSize, hex.EncodeToString(req.MtlHash)), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr JSONInclusionProofResponse
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &pb.LogInclusionProofResponse{
		AuditPath: cr.Proof,
		LeafIndex: cr.Number,
		TreeSize:  cr.TreeSize,
	}, nil
}
func (self *HTTPRESTClient) LogConsistencyProof(ctx context.Context, req *pb.LogConsistencyProofRequest) (*pb.LogConsistencyProofResponse, error) {
	contents, _, err := self.makeLogRequest(req.Log, "GET", fmt.Sprintf("/tree/%d/consistency/%d", req.TreeSize, req.FromSize), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr JSONConsistencyProofResponse
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &pb.LogConsistencyProofResponse{
		AuditPath: cr.Proof,
		FromSize:  cr.First,
		TreeSize:  cr.Second,
	}, nil
}
func (self *HTTPRESTClient) MapSetValue(ctx context.Context, req *pb.MapSetValueRequest) (*pb.MapSetValueResponse, error) {
	switch req.Action {
	case pb.MapMutationAction_MAP_MUTATION_DELETE:
		contents, _, err := self.makeMapRequest(req.Map, "DELETE", "/key/h/"+hex.EncodeToString(req.Key), nil, nil)
		if err != nil {
			return nil, err
		}
		var aer JSONAddEntryResponse
		err = json.Unmarshal(contents, &aer)
		if err != nil {
			return nil, err
		}
		return &pb.MapSetValueResponse{LeafHash: aer.Hash}, nil
	case pb.MapMutationAction_MAP_MUTATION_SET:
		contents, _, err := self.makeMapRequest(req.Map, "PUT", "/key/h/"+hex.EncodeToString(req.Key), req.Value.LeafInput, nil)
		if err != nil {
			return nil, err
		}
		var aer JSONAddEntryResponse
		err = json.Unmarshal(contents, &aer)
		if err != nil {
			return nil, err
		}
		return &pb.MapSetValueResponse{LeafHash: aer.Hash}, nil
	case pb.MapMutationAction_MAP_MUTATION_UPDATE:
		contents, _, err := self.makeMapRequest(req.Map, "PUT", "/key/h/"+hex.EncodeToString(req.Key), req.Value.LeafInput, [][2]string{
			[2]string{"X-Previous-LeafHash", hex.EncodeToString(req.PrevLeafHash)},
		})
		if err != nil {
			return nil, err
		}
		var aer JSONAddEntryResponse
		err = json.Unmarshal(contents, &aer)
		if err != nil {
			return nil, err
		}
		return &pb.MapSetValueResponse{LeafHash: aer.Hash}, nil
	default:
		return nil, ErrInternalError
	}
}

func parseHeadersForProof(headers http.Header) ([][]byte, error) {
	prv := make([][]byte, 256)
	actualHeaders, ok := headers[http.CanonicalHeaderKey("X-Verified-Proof")]
	if ok {
		for _, h := range actualHeaders {
			for _, commad := range strings.Split(h, ",") {
				bits := strings.SplitN(commad, "/", 2)
				if len(bits) == 2 {
					idx, err := strconv.Atoi(strings.TrimSpace(bits[0]))
					if err != nil {
						return nil, err
					}
					bs, err := hex.DecodeString(strings.TrimSpace(bits[1]))
					if err != nil {
						return nil, err
					}
					if idx < 256 {
						prv[idx] = bs
					}
				}
			}
		}
	}
	return prv, nil
}

func (self *HTTPRESTClient) MapGetValue(ctx context.Context, req *pb.MapGetValueRequest) (*pb.MapGetValueResponse, error) {
	value, headers, err := self.makeMapRequest(req.Map, "GET", fmt.Sprintf("/tree/%d/key/h/%s%s", req.TreeSize, hex.EncodeToString(req.Key), ""), nil, nil)
	if err != nil {
		return nil, err
	}

	prv, err := parseHeadersForProof(headers)
	if err != nil {
		return nil, err
	}

	// TODO - figure out how to get ExtraData to return

	vts, err := strconv.Atoi(headers.Get("X-Verified-TreeSize"))
	if err != nil {
		return nil, err
	}

	return &pb.MapGetValueResponse{
		AuditPath: prv,
		TreeSize:  int64(vts),
		Value: &pb.LeafData{
			LeafInput: value,
		},
	}, nil
}
func (self *HTTPRESTClient) MapTreeHash(ctx context.Context, req *pb.MapTreeHashRequest) (*pb.MapTreeHashResponse, error) {
	contents, _, err := self.makeMapRequest(req.Map, "GET", fmt.Sprintf("/tree/%d", req.TreeSize), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr JSONMapTreeHeadResponse
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &pb.MapTreeHashResponse{
		RootHash: cr.MapHash,
		MutationLog: &pb.LogTreeHashResponse{
			RootHash: cr.LogTreeHead.Hash,
			TreeSize: cr.LogTreeHead.TreeSize,
		},
	}, nil
}
