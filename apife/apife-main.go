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

package apife

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"strconv"

	"golang.org/x/net/context"

	"github.com/continusec/objecthash"
	"github.com/continusec/verifiabledatastructures/api"
	"github.com/continusec/verifiabledatastructures/client"
	"github.com/continusec/verifiabledatastructures/pb"

	"net/http"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const (
	headStr = "head"

	stdFormat = 0
	hexFormat = 1

	rawEntry      = 0
	jsonEntry     = 1
	redactedEntry = 2
	mutationEntry = 3
)

type formatMetadata struct {
	Suffix                              string
	EntryFormat                         int
	Gettable, Addable, Mutation, Redact bool
}

var (
	commonSuffixes = []*formatMetadata{
		{Suffix: "", EntryFormat: rawEntry, Gettable: true, Addable: true},
		{Suffix: "/xjson", EntryFormat: jsonEntry, Gettable: true, Addable: true},
		{Suffix: "/xjson/redactable", EntryFormat: redactedEntry, Addable: true, Redact: true},
		{Suffix: "/xjson/mutation", EntryFormat: mutationEntry, Mutation: true},
	}
)

type apiServer struct {
	service pb.VerifiableDataStructuresServiceServer
}

// CreateRESTHandler creates handlers for the API
func CreateRESTHandler(s pb.VerifiableDataStructuresServiceServer) http.Handler {
	as := &apiServer{service: s}

	r := mux.NewRouter()

	// Create a log
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}", wrapLogFunction(pb.LogType_STRUCT_TYPE_LOG, as.createLogHandler)).Methods("PUT")

	// Delete a log
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}", wrapLogFunction(pb.LogType_STRUCT_TYPE_LOG, as.deleteLogHandler)).Methods("DELETE")

	// List logs
	r.HandleFunc("/v1/account/{account:[0-9]+}/logs", wrapAccountFunction(as.listLogsHandler)).Methods("GET")

	// Remaining log operations, including those on Mutation and Treehead logs
	for _, t := range []struct {
		Prefix            string
		LogType           pb.LogType
		Addable, Mutation bool
	}{
		{Prefix: "/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}", LogType: pb.LogType_STRUCT_TYPE_LOG, Addable: true},
		{Prefix: "/v1/account/{account:[0-9]+}/map/{log:[0-9a-z-_]+}/log/mutation", LogType: pb.LogType_STRUCT_TYPE_MUTATION_LOG, Mutation: true},
		{Prefix: "/v1/account/{account:[0-9]+}/map/{log:[0-9a-z-_]+}/log/treehead", LogType: pb.LogType_STRUCT_TYPE_TREEHEAD_LOG},
	} {
		for _, f := range commonSuffixes {
			if t.Addable && f.Addable {
				// Insert a log entry
				r.HandleFunc(t.Prefix+"/entry"+f.Suffix, wrapLogFunctionWithFormat(t.LogType, f, as.insertEntryHandler)).Methods("POST")
			}

			if f.Gettable || (f.Mutation && t.Mutation) {
				// Get a log entry
				r.HandleFunc(t.Prefix+"/entry/{number:[0-9]+}"+f.Suffix, wrapLogFunctionWithFormat(t.LogType, f, as.getEntryHandler)).Methods("GET")

				// Get multiple entries, last is exclusive
				r.HandleFunc(t.Prefix+"/entries/{first:[0-9]+}-{last:[0-9]+}"+f.Suffix, wrapLogFunctionWithFormat(t.LogType, f, as.getEntriesHandler)).Methods("GET")
			}
		}

		// Get STH
		r.HandleFunc(t.Prefix+"/tree/{treesize:(?:[0-9]+)|head}", wrapLogFunction(t.LogType, as.getLogTreeHashHandler)).Methods("GET")

		// Get inclusion proof by Hash
		r.HandleFunc(t.Prefix+"/tree/{treesize:[0-9]+}/inclusion/h/{hash:[0-9a-f]+}", wrapLogFunction(t.LogType, as.inclusionByHashProofHandler)).Methods("GET")
		r.HandleFunc(t.Prefix+"/tree/{treesize:[0-9]+}/inclusion/s/{strentry:[0-9a-zA-Z-_]+}", wrapLogFunction(t.LogType, as.inclusionByStringProofHandler)).Methods("GET")
		r.HandleFunc(t.Prefix+"/tree/{treesize:[0-9]+}/inclusion/{number:[0-9]+}", wrapLogFunction(t.LogType, as.inclusionByIndexProofHandler)).Methods("GET")

		// Get consistency proof
		r.HandleFunc(t.Prefix+"/tree/{treesize:[0-9]+}/consistency/{oldsize:[0-9]+}", wrapLogFunction(t.LogType, as.getConsistencyProofHandler)).Methods("GET")
	}
	// MAP STUFF

	// Create Map Handler
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}", wrapMapFunction(as.createMapHandler)).Methods("PUT")

	// Delete Map Handler
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}", wrapMapFunction(as.deleteMapHandler)).Methods("DELETE")

	// List maps Handler
	r.HandleFunc("/v1/account/{account:[0-9]+}/maps", wrapAccountFunction(as.listMapsHandler)).Methods("GET")

	for _, h := range []struct {
		KeyFormat int
		Ch        string
	}{
		{KeyFormat: stdFormat, Ch: "s/{key:[0-9a-zA-Z-_]+}"},
		{KeyFormat: hexFormat, Ch: "h/{key:[0-9a-f]+}"},
	} {
		for _, f := range commonSuffixes {
			if f.Addable {
				// Insert and modify map entry
				r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/"+h.Ch+f.Suffix, wrapMapFunctionWithKeyAndFormat(h.KeyFormat, f.EntryFormat, as.setMapEntry)).Methods("PUT")
			}

			if f.Gettable {
				// Get value + proof
				r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}/key/"+h.Ch+f.Suffix, wrapMapFunctionWithKeyAndFormat(h.KeyFormat, f.EntryFormat, as.getMapEntry)).Methods("GET")
			}
		}
		// Delete a map entry
		r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/"+h.Ch, wrapMapFunctionWithKey(h.KeyFormat, as.deleteMapEntryHandler)).Methods("DELETE")
	}

	// Get STH
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}", wrapMapFunction(as.getMapRootHashHandler)).Methods("GET")

	// Make sure we return 200 for OPTIONS requests since handlers below will fall through to us
	r.HandleFunc("/{thing:.*}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}).Methods("OPTIONS")

	// Since we do NO cookie or basic auth, allow CORS
	return handlers.CORS(
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedHeaders([]string{"Authorization", "Accept", "Content-Type"}),
		handlers.ExposedHeaders([]string{"X-Verified-Treesize", "X-Verified-Proof"}),
	)(r)
}

func apiKeyFromRequest(r *http.Request) string {
	headerParts := strings.Split(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if len(headerParts) == 2 {
		if headerParts[0] == "Key" {
			return headerParts[1]
		}
	}
	return ""
}

func accountRefFromRequest(r *http.Request) (map[string]string, *pb.AccountRef) {
	vars := mux.Vars(r)
	return vars, &pb.AccountRef{
		ApiKey: apiKeyFromRequest(r),
		Id:     vars["account"],
	}
}

func logRefFromRequest(r *http.Request, lt pb.LogType) (map[string]string, *pb.LogRef) {
	vars, account := accountRefFromRequest(r)
	return vars, &pb.LogRef{
		Account: account,
		Name:    vars["log"],
		LogType: lt,
	}
}

func mapRefFromRequest(r *http.Request) (map[string]string, *pb.MapRef) {
	vars, account := accountRefFromRequest(r)
	return vars, &pb.MapRef{
		Account: account,
		Name:    vars["map"],
	}
}

func wrapMapFunction(f func(*pb.MapRef, map[string]string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars, mapRef := mapRefFromRequest(r)
		f(mapRef, vars, w, r)
	}
}

func wrapLogFunction(logType pb.LogType, f func(*pb.LogRef, map[string]string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars, logRef := logRefFromRequest(r, logType)
		f(logRef, vars, w, r)
	}
}

func wrapAccountFunction(f func(*pb.AccountRef, map[string]string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars, accRef := accountRefFromRequest(r)
		f(accRef, vars, w, r)
	}
}

func wrapLogFunctionWithFormat(logType pb.LogType, ef *formatMetadata, f func(*pb.LogRef, *formatMetadata, map[string]string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return wrapLogFunction(logType, func(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
		f(log, ef, vars, w, r)
	})
}

func wrapMapFunctionWithKey(keyType int, f func(*pb.MapRef, []byte, map[string]string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return wrapMapFunction(func(vmap *pb.MapRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
		var k []byte
		switch keyType {
		case stdFormat:
			k = []byte(vars["key"])
		case hexFormat:
			var err error
			k, err = hex.DecodeString(vars["key"])
			if err != nil {
				writeResponseHeader(w, api.ErrInvalidRequest)
				return
			}
		default:
			writeResponseHeader(w, api.ErrNotImplemented)
			return
		}
		f(vmap, k, vars, w, r)
	})
}

func wrapMapFunctionWithKeyAndFormat(keyType int, ef int, f func(*pb.MapRef, []byte, int, map[string]string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return wrapMapFunctionWithKey(keyType, func(vmap *pb.MapRef, k []byte, vars map[string]string, w http.ResponseWriter, r *http.Request) {
		f(vmap, k, ef, vars, w, r)
	})
}

func requestContext(r *http.Request) context.Context {
	return context.TODO()
}

func writeResponseHeader(w http.ResponseWriter, err error) {
	switch err {
	case nil:
		w.WriteHeader(http.StatusOK)
	case api.ErrNotAuthorized:
		w.WriteHeader(http.StatusUnauthorized)
	case api.ErrInvalidTreeRange:
		w.WriteHeader(http.StatusBadRequest)
	case api.ErrInvalidJSON:
		w.WriteHeader(http.StatusBadRequest)
	case api.ErrLogUnsafeForAccess:
		w.WriteHeader(http.StatusNotFound)
	case api.ErrNotFound:
		w.WriteHeader(http.StatusNotFound)
	case api.ErrLogAlreadyExists:
		w.WriteHeader(http.StatusConflict)
	case api.ErrAlreadyNotActive: // no deleting a log twice thanks
		w.WriteHeader(http.StatusConflict)
	default:
		log.Printf("Error: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func writeSuccessJSON(w http.ResponseWriter, d interface{}) {
	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(d)
}

func writeSuccessContent(w http.ResponseWriter, val []byte) {
	w.Header().Set("Content-Type", http.DetectContentType(val))
	w.WriteHeader(http.StatusOK)
	w.Write(val)
}

func (as *apiServer) createMapHandler(vmap *pb.MapRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	_, err := as.service.MapCreate(requestContext(r), &pb.MapCreateRequest{Map: vmap})
	writeResponseHeader(w, err)
}

func (as *apiServer) deleteMapHandler(vmap *pb.MapRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	_, err := as.service.MapDelete(requestContext(r), &pb.MapDeleteRequest{Map: vmap})
	writeResponseHeader(w, err)
}

func (as *apiServer) createLogHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	_, err := as.service.LogCreate(requestContext(r), &pb.LogCreateRequest{Log: log})
	writeResponseHeader(w, err)
}

func (as *apiServer) deleteLogHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	_, err := as.service.LogDelete(requestContext(r), &pb.LogDeleteRequest{Log: log})
	writeResponseHeader(w, err)
}

func (as *apiServer) listLogsHandler(acc *pb.AccountRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	logs, err := as.service.LogList(requestContext(r), &pb.LogListRequest{Account: acc})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}
	rv := make([]*client.JSONLogInfoResponse, len(logs.Logs))
	for idx, l := range logs.Logs {
		rv[idx] = &client.JSONLogInfoResponse{Name: l.Name}
	}
	writeSuccessJSON(w, &client.JSONLogListResponse{Items: rv})
}

func (as *apiServer) listMapsHandler(acc *pb.AccountRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	maps, err := as.service.MapList(requestContext(r), &pb.MapListRequest{Account: acc})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}
	rv := make([]*client.JSONMapInfoResponse, len(maps.Maps))
	for idx, m := range maps.Maps {
		rv[idx] = &client.JSONMapInfoResponse{Name: m.Name}
	}
	writeSuccessJSON(w, &client.JSONMapListResponse{Items: rv})
}

func (as *apiServer) getLogTreeHashHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	var treeSize int64
	if vars["treesize"] == headStr {
		treeSize = 0
	} else {
		ts, err := strconv.Atoi(vars["treesize"])
		if err != nil {
			writeResponseHeader(w, api.ErrInvalidRequest)
			return
		}
		treeSize = int64(ts)
	}

	resp, err := as.service.LogTreeHash(requestContext(r), &pb.LogTreeHashRequest{
		Log:      log,
		TreeSize: treeSize,
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, &client.JSONLogTreeHeadResponse{
		TreeSize: resp.TreeSize,
		Hash:     resp.RootHash,
	})
}

func (as *apiServer) getConsistencyProofHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	var treeSize int
	if vars["treesize"] == headStr {
		treeSize = 0
	} else {
		var err error
		treeSize, err = strconv.Atoi(vars["treesize"])
		if err != nil {
			writeResponseHeader(w, api.ErrInvalidRequest)
			return
		}
	}
	oldSize, err := strconv.Atoi(vars["oldsize"])
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	resp, err := as.service.LogConsistencyProof(requestContext(r), &pb.LogConsistencyProofRequest{
		Log:      log,
		FromSize: int64(oldSize),
		TreeSize: int64(treeSize),
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, &client.JSONConsistencyProofResponse{
		First:  resp.FromSize,
		Second: resp.TreeSize,
		Proof:  resp.AuditPath,
	})
}

func (as *apiServer) inclusionProofHandler(log *pb.LogRef, vars map[string]string, partial *pb.LogInclusionProofRequest, w http.ResponseWriter, r *http.Request) {
	treeSize, err := strconv.Atoi(vars["treesize"])
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	partial.Log = log
	partial.TreeSize = int64(treeSize)

	resp, err := as.service.LogInclusionProof(requestContext(r), partial)
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, &client.JSONInclusionProofResponse{
		Number:   resp.LeafIndex,
		TreeSize: resp.TreeSize,
		Proof:    resp.AuditPath,
	})
}

func (as *apiServer) inclusionByIndexProofHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	number, err := strconv.Atoi(vars["number"])
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	as.inclusionProofHandler(log, vars, &pb.LogInclusionProofRequest{
		LeafIndex: int64(number),
	}, w, r)
}

func (as *apiServer) inclusionByStringProofHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	as.inclusionProofHandler(log, vars, &pb.LogInclusionProofRequest{
		MtlHash: client.LeafMerkleTreeHash([]byte(vars["strentry"])),
	}, w, r)
}

func (as *apiServer) inclusionByHashProofHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	mtlHash, err := hex.DecodeString(vars["hash"])
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	as.inclusionProofHandler(log, vars, &pb.LogInclusionProofRequest{
		MtlHash: mtlHash,
	}, w, r)
}

func redactJSON(b []byte) ([]byte, error) {
	var o interface{}
	err := json.Unmarshal(b, &o)
	if err != nil {
		return nil, err
	}

	o, err = objecthash.Redactable(o)
	if err != nil {
		return nil, err
	}

	return json.Marshal(o)
}

func (as *apiServer) insertEntryHandler(log *pb.LogRef, ef *formatMetadata, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	ld, err := createLeafData(body, ef.EntryFormat)
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	resp, err := as.service.LogAddEntry(requestContext(r), &pb.LogAddEntryRequest{
		Log:  log,
		Data: ld,
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, &client.JSONAddEntryResponse{
		Hash: resp.LeafHash,
	})
}

func (as *apiServer) getEntryHandler(log *pb.LogRef, ef *formatMetadata, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	number, err := strconv.Atoi(vars["number"])
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	resp, err := as.service.LogFetchEntries(requestContext(r), &pb.LogFetchEntriesRequest{
		Log:   log,
		First: int64(number),
		Last:  int64(number + 1),
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	// Make sure we get exactly 1 back
	if len(resp.Values) != 1 {
		writeResponseHeader(w, api.ErrNotFound)
		return
	}

	writeResponseData(w, resp.Values[0], ef.EntryFormat)
}

func (as *apiServer) getEntriesHandler(log *pb.LogRef, ef *formatMetadata, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	first, err := strconv.Atoi(vars["first"])
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	last, err := strconv.Atoi(vars["last"])
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	resp, err := as.service.LogFetchEntries(requestContext(r), &pb.LogFetchEntriesRequest{
		Log:   log,
		First: int64(first),
		Last:  int64(last),
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	rv := make([]*client.JSONGetEntryResponse, len(resp.Values))
	for i, v := range resp.Values {
		d, err := getResponseData(v, ef.EntryFormat)
		if err != nil {
			writeResponseHeader(w, err)
			return
		}

		rv[i] = &client.JSONGetEntryResponse{
			Number: int64(first + i),
			Data:   d,
		}
	}
	writeSuccessJSON(w, &client.JSONGetEntriesResponse{
		Entries: rv,
	})
}

func (as *apiServer) getMapRootHashHandler(vmap *pb.MapRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	var treeSize int
	if vars["treesize"] == headStr {
		treeSize = 0
	} else {
		var err error
		treeSize, err = strconv.Atoi(vars["treesize"])
		if err != nil {
			writeResponseHeader(w, api.ErrInvalidRequest)
			return
		}
	}

	resp, err := as.service.MapTreeHash(requestContext(r), &pb.MapTreeHashRequest{
		Map:      vmap,
		TreeSize: int64(treeSize),
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, &client.JSONMapTreeHeadResponse{
		MapHash: resp.RootHash,
		LogTreeHead: &client.JSONLogTreeHeadResponse{
			Hash:     resp.MutationLog.RootHash,
			TreeSize: resp.MutationLog.TreeSize,
		},
	})
}

func (as *apiServer) queueMapMutation(vmap *pb.MapRef, partial *pb.MapSetValueRequest, w http.ResponseWriter, r *http.Request) {
	partial.Map = vmap
	resp, err := as.service.MapSetValue(requestContext(r), partial)
	if err != nil {
		writeResponseHeader(w, err)
		return
	}
	writeSuccessJSON(w, &client.JSONAddEntryResponse{
		Hash: resp.LeafHash,
	})
}

func (as *apiServer) deleteMapEntryHandler(vmap *pb.MapRef, key []byte, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	as.queueMapMutation(vmap, &pb.MapSetValueRequest{
		Action: pb.MapMutationAction_MAP_MUTATION_DELETE,
		Key:    key,
	}, w, r)
}

func (as *apiServer) getMapEntry(vmap *pb.MapRef, key []byte, ef int, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	var treeSize int
	if vars["treesize"] == headStr {
		treeSize = 0
	} else {
		var err error
		treeSize, err = strconv.Atoi(vars["treesize"])
		if err != nil {
			writeResponseHeader(w, api.ErrInvalidRequest)
			return
		}
	}

	resp, err := as.service.MapGetValue(requestContext(r), &pb.MapGetValueRequest{
		Map:      vmap,
		TreeSize: int64(treeSize),
		Key:      key,
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	w.Header().Set("X-Verified-TreeSize", strconv.Itoa(int(resp.TreeSize)))
	for i, p := range resp.AuditPath {
		if len(p) > 0 {
			w.Header().Add("X-Verified-Proof", strconv.Itoa(i)+"/"+hex.EncodeToString(p))
		}
	}

	writeResponseData(w, resp.Value, ef)
}

func getResponseData(ld *pb.LeafData, ef int) ([]byte, error) {
	switch ef {
	case rawEntry:
		return ld.LeafInput, nil
	case jsonEntry:
		return ld.ExtraData, nil
	default:
		return nil, api.ErrInvalidRequest

	}
}

func writeResponseData(w http.ResponseWriter, ld *pb.LeafData, ef int) {
	data, err := getResponseData(ld, ef)
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}
	writeSuccessContent(w, data)
}

func createLeafData(body []byte, ef int) (*pb.LeafData, error) {
	switch ef {
	case rawEntry:
		return &pb.LeafData{LeafInput: body}, nil
	case jsonEntry:
		oh, err := objecthash.CommonJSONHash(body)
		if err != nil {
			return nil, api.ErrInvalidRequest
		}
		return &pb.LeafData{LeafInput: oh, ExtraData: body}, nil
	case redactedEntry:
		var obj interface{}
		err := json.Unmarshal(body, &obj)
		if err != nil {
			return nil, api.ErrInvalidRequest
		}
		redactable, err := objecthash.Redactable(obj)
		if err != nil {
			return nil, api.ErrInvalidRequest
		}
		oh, err := objecthash.ObjectHash(redactable)
		if err != nil {
			return nil, api.ErrInvalidRequest
		}
		rb, err := json.Marshal(redactable)
		if err != nil {
			return nil, api.ErrInvalidRequest
		}
		return &pb.LeafData{LeafInput: oh, ExtraData: rb}, nil
	default:
		return nil, api.ErrInvalidRequest
	}
}

func (as *apiServer) setMapEntry(vmap *pb.MapRef, key []byte, ef int, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	prevLeafHashString := strings.TrimSpace(r.Header.Get("X-Previous-LeafHash"))
	var prevLeafHash []byte
	if len(prevLeafHashString) > 0 {
		var err error
		prevLeafHash, err = hex.DecodeString(prevLeafHashString)
		if err != nil {
			writeResponseHeader(w, api.ErrInvalidRequest)
			return
		}
	}

	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	ld, err := createLeafData(body, ef)
	if err != nil {
		writeResponseHeader(w, api.ErrInvalidRequest)
		return
	}

	if len(prevLeafHash) == 0 {
		as.queueMapMutation(vmap, &pb.MapSetValueRequest{
			Action: pb.MapMutationAction_MAP_MUTATION_SET,
			Key:    key,
			Value:  ld,
		}, w, r)
	} else { // must be an update
		as.queueMapMutation(vmap, &pb.MapSetValueRequest{
			Action:       pb.MapMutationAction_MAP_MUTATION_UPDATE,
			Key:          key,
			Value:        ld,
			PrevLeafHash: prevLeafHash,
		}, w, r)
	}
}
