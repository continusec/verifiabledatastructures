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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/util"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	restAPIVersion = "/v2"
)

// HTTPRESTClient provides a way to access the API over HTTP REST.
// Where possible it is suggested that the GRPCClient be used in preference.
type HTTPRESTClient struct {
	// BaseURL is the URL (with no trailing slash) of the server, e.g. http://localhost:8081
	BaseURL string

	// HTTPClient is the client to use for sending requests.
	HTTPClient *http.Client
}

// Dial returns a server object read to speak with directly or wrap.
func (c *HTTPRESTClient) Dial() (pb.VerifiableDataStructuresServiceServer, error) {
	return (*httpRestImpl)(c), nil
}

// MustDial is a convenience method that exits with a fatal error if the operation fails
func (c *HTTPRESTClient) MustDial() pb.VerifiableDataStructuresServiceServer {
	rv, err := c.Dial()
	if err != nil {
		log.Fatal(err)
	}
	return rv
}

type httpRestImpl HTTPRESTClient

func (c *httpRestImpl) makeLogRequest(log *pb.LogRef, method, path string, data []byte, headers [][2]string) ([]byte, http.Header, error) {
	prefix := ""
	switch log.LogType {
	case pb.LogType_STRUCT_TYPE_LOG:
		prefix = fmt.Sprintf("/account/%s/log/%s", log.Account.Id, log.Name)
	case pb.LogType_STRUCT_TYPE_MUTATION_LOG:
		prefix = fmt.Sprintf("/account/%s/map/%s/log/mutation", log.Account.Id, log.Name)
	case pb.LogType_STRUCT_TYPE_TREEHEAD_LOG:
		prefix = fmt.Sprintf("/account/%s/map/%s/log/treehead", log.Account.Id, log.Name)
	default:
		return nil, nil, util.ErrInvalidRequest
	}
	return c.makeRequest(log.Account, method, prefix+path, data, headers)
}

func (c *httpRestImpl) makeMapRequest(vmap *pb.MapRef, method, path string, data []byte, headers [][2]string) ([]byte, http.Header, error) {
	return c.makeRequest(vmap.Account, method, fmt.Sprintf("/account/%s/map/%s", vmap.Account.Id, vmap.Name)+path, data, headers)
}

// Intended for internal use, MakeRequest makes an HTTP request and converts the error
// code to those appropriate for the rest of the library.
func (c *httpRestImpl) makeRequest(account *pb.AccountRef, method, path string, data []byte, headers [][2]string) ([]byte, http.Header, error) {
	req, err := http.NewRequest(method, c.BaseURL+restAPIVersion+path, bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	if account.ApiKey != "" {
		req.Header.Set("Authorization", "Key "+account.ApiKey)
	}
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}

	httpC := c.HTTPClient
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
	case http.StatusOK:
		return contents, resp.Header, nil
	case http.StatusUnauthorized:
		return nil, nil, status.Error(codes.PermissionDenied, "")
	case http.StatusBadRequest:
		return nil, nil, status.Error(codes.InvalidArgument, "")
	case http.StatusNotFound:
		return nil, nil, status.Error(codes.NotFound, "")
	default:
		return nil, nil, status.Error(codes.Internal, "")
	}
}

// LogAddEntry adds an entry to the log.
func (c *httpRestImpl) LogAddEntry(ctx context.Context, req *pb.LogAddEntryRequest) (*pb.LogAddEntryResponse, error) {
	reqData, err := json.Marshal(req.Value)
	if err != nil {
		return nil, err
	}
	contents, _, err := c.makeLogRequest(req.Log, "POST", "/entry/extra", reqData, nil)
	if err != nil {
		return nil, err
	}
	var rv pb.LogAddEntryResponse
	err = json.Unmarshal(contents, &rv)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// LogFetchEntries fetches entries from the log
func (c *httpRestImpl) LogFetchEntries(ctx context.Context, req *pb.LogFetchEntriesRequest) (*pb.LogFetchEntriesResponse, error) {
	contents, _, err := c.makeLogRequest(req.Log, "GET", fmt.Sprintf("/entries/%d-%d%s", req.First, req.Last, "/extra"), nil, nil)
	if err != nil {
		return nil, err
	}

	var rv pb.LogFetchEntriesResponse
	err = json.Unmarshal(contents, &rv)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// LogTreeHash fetches the tree hash from the log
func (c *httpRestImpl) LogTreeHash(ctx context.Context, req *pb.LogTreeHashRequest) (*pb.LogTreeHashResponse, error) {
	contents, _, err := c.makeLogRequest(req.Log, "GET", fmt.Sprintf("/tree/%d", req.TreeSize), nil, nil)
	if err != nil {
		return nil, err
	}
	var rv pb.LogTreeHashResponse
	err = json.Unmarshal(contents, &rv)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// LogInclusionProof fetches an inclusion proof from the logs
func (c *httpRestImpl) LogInclusionProof(ctx context.Context, req *pb.LogInclusionProofRequest) (*pb.LogInclusionProofResponse, error) {
	if len(req.MtlHash) == 0 {
		contents, _, err := c.makeLogRequest(req.Log, "GET", fmt.Sprintf("/tree/%d/inclusion/%d", req.TreeSize, req.LeafIndex), nil, nil)
		if err != nil {
			return nil, err
		}
		var rv pb.LogInclusionProofResponse
		err = json.Unmarshal(contents, &rv)
		if err != nil {
			return nil, err
		}
		return &rv, nil
	}
	contents, _, err := c.makeLogRequest(req.Log, "GET", fmt.Sprintf("/tree/%d/inclusion/h/%s", req.TreeSize, hex.EncodeToString(req.MtlHash)), nil, nil)
	if err != nil {
		return nil, err
	}
	var rv pb.LogInclusionProofResponse
	err = json.Unmarshal(contents, &rv)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// LogConsistencyProof fetches a consistency proof from the log
func (c *httpRestImpl) LogConsistencyProof(ctx context.Context, req *pb.LogConsistencyProofRequest) (*pb.LogConsistencyProofResponse, error) {
	contents, _, err := c.makeLogRequest(req.Log, "GET", fmt.Sprintf("/tree/%d/consistency/%d", req.TreeSize, req.FromSize), nil, nil)
	if err != nil {
		return nil, err
	}
	var rv pb.LogConsistencyProofResponse
	err = json.Unmarshal(contents, &rv)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// MapSetValue sets a value in the map
func (c *httpRestImpl) MapSetValue(ctx context.Context, req *pb.MapSetValueRequest) (*pb.MapSetValueResponse, error) {
	switch req.Mutation.Action {
	case "delete":
		contents, _, err := c.makeMapRequest(req.Map, "DELETE", "/key/h/"+hex.EncodeToString(req.Mutation.Key), nil, nil)
		if err != nil {
			return nil, err
		}
		var rv pb.MapSetValueResponse
		err = json.Unmarshal(contents, &rv)
		if err != nil {
			return nil, err
		}
		return &rv, nil
	case "set":
		reqData, err := json.Marshal(req.Mutation.Value)
		if err != nil {
			return nil, err
		}
		contents, _, err := c.makeMapRequest(req.Map, "PUT", "/key/h/"+hex.EncodeToString(req.Mutation.Key)+"/extra", reqData, nil)
		if err != nil {
			return nil, err
		}
		var rv pb.MapSetValueResponse
		err = json.Unmarshal(contents, &rv)
		if err != nil {
			return nil, err
		}
		return &rv, nil
	case "update":
		reqData, err := json.Marshal(req.Mutation.Value)
		if err != nil {
			return nil, err
		}
		contents, _, err := c.makeMapRequest(req.Map, "PUT", "/key/h/"+hex.EncodeToString(req.Mutation.Key)+"/extra", reqData, [][2]string{
			[2]string{"X-Previous-LeafHash", hex.EncodeToString(req.Mutation.PreviousLeafHash)},
		})
		if err != nil {
			return nil, err
		}
		var rv pb.MapSetValueResponse
		err = json.Unmarshal(contents, &rv)
		if err != nil {
			return nil, err
		}
		return &rv, nil
	default:
		return nil, util.ErrInvalidRequest
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

// MapGetValue gets the value from the map
func (c *httpRestImpl) MapGetValue(ctx context.Context, req *pb.MapGetValueRequest) (*pb.MapGetValueResponse, error) {
	value, headers, err := c.makeMapRequest(req.Map, "GET", fmt.Sprintf("/tree/%d/key/h/%s%s", req.TreeSize, hex.EncodeToString(req.Key), "/extra"), nil, nil)
	if err != nil {
		return nil, err
	}

	prv, err := parseHeadersForProof(headers)
	if err != nil {
		return nil, err
	}

	vts, err := strconv.Atoi(headers.Get("X-Verified-TreeSize"))
	if err != nil {
		return nil, err
	}

	var rv pb.LeafData
	err = json.Unmarshal(value, &rv)
	if err != nil {
		return nil, err
	}

	return &pb.MapGetValueResponse{
		AuditPath: prv,
		TreeSize:  int64(vts),
		Value:     &rv,
	}, nil
}

// MapTreeHash gets the tree hash from the map
func (c *httpRestImpl) MapTreeHash(ctx context.Context, req *pb.MapTreeHashRequest) (*pb.MapTreeHashResponse, error) {
	contents, _, err := c.makeMapRequest(req.Map, "GET", fmt.Sprintf("/tree/%d", req.TreeSize), nil, nil)
	if err != nil {
		return nil, err
	}
	var rv pb.MapTreeHashResponse
	err = json.Unmarshal(contents, &rv)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}
