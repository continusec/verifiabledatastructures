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
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/grpc/status"

	"github.com/continusec/objecthash"
	"github.com/continusec/verifiabledatastructures/assets"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"github.com/Guardtime/verifiabledatastructures/util"
)

const (
	headStr = "head"

	stdFormat = 0
	hexFormat = 1

	rawEntry      = 0
	jsonEntry     = 1
	redactedEntry = 2
	extraEntry    = 4

	version = "/v2"
)

type formatMetadata struct {
	Suffix           string
	EntryFormat      int
	Gettable, Redact bool
}

var (
	commonSuffixes = []*formatMetadata{
		{Suffix: "", EntryFormat: rawEntry, Gettable: true},
		{Suffix: "/xjson", EntryFormat: jsonEntry, Gettable: true},
		{Suffix: "/xjson/redactable", EntryFormat: redactedEntry, Redact: true},
		{Suffix: "/extra", EntryFormat: extraEntry, Gettable: true},
	}
)

type apiServer struct {
	service pb.VerifiableDataStructuresServiceServer
	cc      ContextCreator
}

// ContextCreator is a function that can produce a context object based on a request.
// If not specified, a background context will be used.
type ContextCreator func(*http.Request) context.Context

// CreateRESTHandler creates handlers for the API
// Leave cc nil unless you need to be able to create a specialized context, e.g. GAE
func CreateRESTHandler(s pb.VerifiableDataStructuresServiceServer, cc ContextCreator) http.Handler {
	as := &apiServer{service: s}
	if cc == nil {
		as.cc = defaultRequestContext
	} else {
		as.cc = cc
	}

	r := mux.NewRouter()

	// Remaining log operations, including those on Mutation and Treehead logs
	for _, t := range []struct {
		Prefix            string
		LogType           pb.LogType
		Addable, Mutation bool
	}{
		{Prefix: version + "/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}", LogType: pb.LogType_STRUCT_TYPE_LOG, Addable: true},
		{Prefix: version + "/account/{account:[0-9]+}/map/{log:[0-9a-z-_]+}/log/mutation", LogType: pb.LogType_STRUCT_TYPE_MUTATION_LOG, Mutation: true},
		{Prefix: version + "/account/{account:[0-9]+}/map/{log:[0-9a-z-_]+}/log/treehead", LogType: pb.LogType_STRUCT_TYPE_TREEHEAD_LOG},
	} {
		for _, f := range commonSuffixes {
			// Insert a log entry
			r.HandleFunc(t.Prefix+"/entry"+f.Suffix, wrapLogFunctionWithFormat(t.LogType, f, as.insertEntryHandler)).Methods("POST")

			if f.Gettable {
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

	for _, h := range []struct {
		KeyFormat int
		Ch        string
	}{
		{KeyFormat: stdFormat, Ch: "s/{key:[0-9a-zA-Z-_]+}"},
		{KeyFormat: hexFormat, Ch: "h/{key:[0-9a-f]+}"},
	} {
		for _, f := range commonSuffixes {
			// Insert and modify map entry
			r.HandleFunc(version+"/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/"+h.Ch+f.Suffix, wrapMapFunctionWithKeyAndFormat(h.KeyFormat, f.EntryFormat, as.setMapEntry)).Methods("PUT")

			if f.Gettable {
				// Get value + proof
				r.HandleFunc(version+"/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}/key/"+h.Ch+f.Suffix, wrapMapFunctionWithKeyAndFormat(h.KeyFormat, f.EntryFormat, as.getMapEntry)).Methods("GET")
			}
		}
		// Delete a map entry
		r.HandleFunc(version+"/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/"+h.Ch, wrapMapFunctionWithKey(h.KeyFormat, as.deleteMapEntryHandler)).Methods("DELETE")
	}

	// Get STH
	r.HandleFunc(version+"/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}", wrapMapFunction(as.getMapRootHashHandler)).Methods("GET")

	// Make sure we return 200 for OPTIONS requests since handlers below will fall through to us
	r.HandleFunc("/{thing:.*}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}).Methods("OPTIONS")

	r.HandleFunc("/", staticHandler("text/html", "index.html"))
	r.HandleFunc("/continusec.js", staticHandler("text/javascript", "continusec.js"))
	r.HandleFunc("/favicon.ico", staticHandler("image/x-icon", "favicon.ico"))
	r.HandleFunc("/log.js", staticHandler("text/javascript", "log.js"))
	r.HandleFunc("/logo.png", staticHandler("image/png", "logo.png"))
	r.HandleFunc("/main.css", staticHandler("text/css", "main.css"))

	// Since we do NO cookie or basic auth, allow CORS
	return handlers.CORS(
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedHeaders([]string{"Authorization", "Accept", "Content-Type"}),
		handlers.ExposedHeaders([]string{"X-Verified-Treesize", "X-Verified-Proof"}),
	)(r)
}

func staticHandler(mime, name string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := assets.Asset("assets/static/" + name)
		if err != nil {
			writeResponseHeader(w, err)
			return
		}
		w.Header().Set("Content-Type", mime)
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
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
				writeResponseHeader(w, util.ErrInvalidRequest)
				return
			}
		default:
			writeResponseHeader(w, util.ErrNotImplemented)
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

func defaultRequestContext(r *http.Request) context.Context {
	return context.Background()
}

func writeResponseHeader(w http.ResponseWriter, err error) {
	if err == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	s, ok := status.FromError(err)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch s.Code() {
	case codes.PermissionDenied:
		w.WriteHeader(http.StatusUnauthorized)
	case codes.InvalidArgument:
		w.WriteHeader(http.StatusBadRequest)
	case codes.NotFound:
		w.WriteHeader(http.StatusNotFound)
	default:
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

func (as *apiServer) getLogTreeHashHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	var treeSize int64
	if vars["treesize"] == headStr {
		treeSize = 0
	} else {
		ts, err := strconv.Atoi(vars["treesize"])
		if err != nil {
			writeResponseHeader(w, util.ErrInvalidRequest)
			return
		}
		treeSize = int64(ts)
	}

	resp, err := as.service.LogTreeHash(as.cc(r), &pb.LogTreeHashRequest{
		Log:      log,
		TreeSize: treeSize,
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, resp)
}

func (as *apiServer) getConsistencyProofHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	var treeSize int
	if vars["treesize"] == headStr {
		treeSize = 0
	} else {
		var err error
		treeSize, err = strconv.Atoi(vars["treesize"])
		if err != nil {
			writeResponseHeader(w, util.ErrInvalidRequest)
			return
		}
	}
	oldSize, err := strconv.Atoi(vars["oldsize"])
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	resp, err := as.service.LogConsistencyProof(as.cc(r), &pb.LogConsistencyProofRequest{
		Log:      log,
		FromSize: int64(oldSize),
		TreeSize: int64(treeSize),
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, resp)
}

func (as *apiServer) inclusionProofHandler(log *pb.LogRef, vars map[string]string, partial *pb.LogInclusionProofRequest, w http.ResponseWriter, r *http.Request) {
	treeSize, err := strconv.Atoi(vars["treesize"])
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	partial.Log = log
	partial.TreeSize = int64(treeSize)

	resp, err := as.service.LogInclusionProof(as.cc(r), partial)
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, resp)
}

func (as *apiServer) inclusionByIndexProofHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	number, err := strconv.Atoi(vars["number"])
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	as.inclusionProofHandler(log, vars, &pb.LogInclusionProofRequest{
		LeafIndex: int64(number),
	}, w, r)
}

func (as *apiServer) inclusionByStringProofHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	as.inclusionProofHandler(log, vars, &pb.LogInclusionProofRequest{
		MtlHash: util.LeafMerkleTreeHash([]byte(vars["strentry"])),
	}, w, r)
}

func (as *apiServer) inclusionByHashProofHandler(log *pb.LogRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	mtlHash, err := hex.DecodeString(vars["hash"])
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	as.inclusionProofHandler(log, vars, &pb.LogInclusionProofRequest{
		MtlHash: mtlHash,
	}, w, r)
}

func (as *apiServer) insertEntryHandler(log *pb.LogRef, ef *formatMetadata, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	ld, err := createLeafData(body, ef.EntryFormat)
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	resp, err := as.service.LogAddEntry(as.cc(r), &pb.LogAddEntryRequest{
		Log:   log,
		Value: ld,
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, resp)

}

func (as *apiServer) getEntryHandler(log *pb.LogRef, ef *formatMetadata, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	number, err := strconv.Atoi(vars["number"])
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	resp, err := as.service.LogFetchEntries(as.cc(r), &pb.LogFetchEntriesRequest{
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
		writeResponseHeader(w, util.ErrNotFound)
		return
	}

	writeResponseData(w, resp.Values[0], ef.EntryFormat)
}

func (as *apiServer) getEntriesHandler(log *pb.LogRef, ef *formatMetadata, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	first, err := strconv.Atoi(vars["first"])
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	last, err := strconv.Atoi(vars["last"])
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	resp, err := as.service.LogFetchEntries(as.cc(r), &pb.LogFetchEntriesRequest{
		Log:   log,
		First: int64(first),
		Last:  int64(last),
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, resp)
}

func (as *apiServer) getMapRootHashHandler(vmap *pb.MapRef, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	var treeSize int
	if vars["treesize"] == headStr {
		treeSize = 0
	} else {
		var err error
		treeSize, err = strconv.Atoi(vars["treesize"])
		if err != nil {
			writeResponseHeader(w, util.ErrInvalidRequest)
			return
		}
	}

	resp, err := as.service.MapTreeHash(as.cc(r), &pb.MapTreeHashRequest{
		Map:      vmap,
		TreeSize: int64(treeSize),
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}

	writeSuccessJSON(w, resp)

}

func (as *apiServer) queueMapMutation(vmap *pb.MapRef, mut *pb.MapMutation, w http.ResponseWriter, r *http.Request) {
	resp, err := as.service.MapSetValue(as.cc(r), &pb.MapSetValueRequest{
		Map:      vmap,
		Mutation: mut,
	})
	if err != nil {
		writeResponseHeader(w, err)
		return
	}
	writeSuccessJSON(w, resp)
}

func (as *apiServer) deleteMapEntryHandler(vmap *pb.MapRef, key []byte, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	as.queueMapMutation(vmap, &pb.MapMutation{
		Action: "delete",
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
			writeResponseHeader(w, util.ErrInvalidRequest)
			return
		}
	}

	resp, err := as.service.MapGetValue(as.cc(r), &pb.MapGetValueRequest{
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
	case extraEntry:
		return json.Marshal(ld)
	default:
		return nil, util.ErrInvalidRequest
	}
}

func writeResponseData(w http.ResponseWriter, ld *pb.LeafData, ef int) {
	data, err := getResponseData(ld, ef)
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
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
			return nil, util.ErrInvalidRequest
		}
		return &pb.LeafData{LeafInput: oh, ExtraData: body, Format: pb.DataFormat_JSON}, nil
	case redactedEntry:
		var obj interface{}
		err := json.Unmarshal(body, &obj)
		if err != nil {
			return nil, util.ErrInvalidRequest
		}
		redactable, err := objecthash.Redactable(obj)
		if err != nil {
			return nil, util.ErrInvalidRequest
		}
		oh, err := objecthash.ObjectHash(redactable)
		if err != nil {
			return nil, util.ErrInvalidRequest
		}
		rb, err := json.Marshal(redactable)
		if err != nil {
			return nil, util.ErrInvalidRequest
		}
		return &pb.LeafData{LeafInput: oh, ExtraData: rb, Format: pb.DataFormat_JSON}, nil
	case extraEntry:
		var req pb.LeafData
		err := json.Unmarshal(body, &req)
		if err != nil {
			return nil, err
		}
		return &req, nil
	default:
		return nil, util.ErrInvalidRequest
	}
}

func (as *apiServer) setMapEntry(vmap *pb.MapRef, key []byte, ef int, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	prevLeafHashString := strings.TrimSpace(r.Header.Get("X-Previous-LeafHash"))
	var prevLeafHash []byte
	if len(prevLeafHashString) > 0 {
		var err error
		prevLeafHash, err = hex.DecodeString(prevLeafHashString)
		if err != nil {
			writeResponseHeader(w, util.ErrInvalidRequest)
			return
		}
	}

	body, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	ld, err := createLeafData(body, ef)
	if err != nil {
		writeResponseHeader(w, util.ErrInvalidRequest)
		return
	}

	if len(prevLeafHash) == 0 {
		as.queueMapMutation(vmap, &pb.MapMutation{
			Action: "set",
			Key:    key,
			Value:  ld,
		}, w, r)
	} else { // must be an update
		as.queueMapMutation(vmap, &pb.MapMutation{
			Action:           "update",
			Key:              key,
			Value:            ld,
			PreviousLeafHash: prevLeafHash,
		}, w, r)
	}
}
