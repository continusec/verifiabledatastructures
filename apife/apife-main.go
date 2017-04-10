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
	"context"
	"log"

	"github.com/continusec/verifiabledatastructures/api"
	vdbclient "github.com/continusec/verifiabledatastructures/client"

	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const (
	logTypeUser        = int8(0)
	logTypeMapMutation = int8(1)
	logTypeMapTreeHead = int8(2)
)

type apiServer struct {
	clientFactory vdbclient.Service
}

// CreateHandler creates handlers for the API
func CreateHandler(clif vdbclient.Service) http.Handler {
	as := &apiServer{clientFactory: clif}

	r := mux.NewRouter()

	// Create a log
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}", as.wrapLogFunction(logTypeUser, createLogHandler)).Methods("PUT")

	// Delete a log
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}", as.wrapLogFunction(logTypeUser, deleteLogHandler)).Methods("DELETE")

	// List logs
	r.HandleFunc("/v1/account/{account:[0-9]+}/logs", as.wrapClientHandler(listLogsHandler)).Methods("GET")

	// Insert a log entry
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry", as.wrapLogFunction(logTypeUser, insertEntryHandler)).Methods("POST")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/xjson", as.wrapLogFunction(logTypeUser, insertXJsonEntryHandler)).Methods("POST")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/xjson/redactable", as.wrapLogFunction(logTypeUser, insertRedactableXJsonEntryHandler)).Methods("POST")

	// Get a log entry
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/{number:[0-9]+}", as.wrapLogFunction(logTypeUser, getEntryHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/{number:[0-9]+}/xjson", as.wrapLogFunction(logTypeUser, getXJsonEntryHandler)).Methods("GET")

	// Get multiple entries, last is exclusive
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entries/{first:[0-9]+}-{last:[0-9]+}", as.wrapLogFunction(logTypeUser, getEntriesHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entries/{first:[0-9]+}-{last:[0-9]+}/xjson", as.wrapLogFunction(logTypeUser, getXJsonEntriesHandler)).Methods("GET")

	// Get STH
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}", as.wrapLogFunction(logTypeUser, getSTHHandler)).Methods("GET")

	// Get inclusion proof by Hash
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/inclusion/h/{hash:[0-9a-f]+}", as.wrapLogFunction(logTypeUser, inclusionByHashProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/inclusion/s/{strentry:[0-9a-zA-Z-_]+}", as.wrapLogFunction(logTypeUser, inclusionByStringProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/inclusion/{number:[0-9]+}", as.wrapLogFunction(logTypeUser, inclusionByIndexProofHandler)).Methods("GET")

	// Get consistency proof
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/consistency/{oldsize:[0-9]+}", as.wrapLogFunction(logTypeUser, getConsistencyProofHandler)).Methods("GET")

	// MAP STUFF

	// Create Map Handler
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}", as.wrapClientHandler(createMapHandler)).Methods("PUT")

	// Delete Map Handler
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}", as.wrapClientHandler(deleteMapHandler)).Methods("DELETE")

	// List maps Handler
	r.HandleFunc("/v1/account/{account:[0-9]+}/maps", as.wrapClientHandler(listMapsHandler)).Methods("GET")

	// Insert and modify map entry
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/h/{key:[0-9a-f]+}", as.createSetMapEntryHandler("hex", "std")).Methods("PUT")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/s/{key:[0-9a-zA-Z-_]+}", as.createSetMapEntryHandler("str", "std")).Methods("PUT")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/h/{key:[0-9a-f]+}/xjson", as.createSetMapEntryHandler("hex", "xjson")).Methods("PUT")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/s/{key:[0-9a-zA-Z-_]+}/xjson", as.createSetMapEntryHandler("str", "xjson")).Methods("PUT")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/h/{key:[0-9a-f]+}/xjson/redactable", as.createSetMapEntryHandler("hex", "redactablejson")).Methods("PUT")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/s/{key:[0-9a-zA-Z-_]+}/xjson/redactable", as.createSetMapEntryHandler("str", "redactablejson")).Methods("PUT")

	// Get value + proof
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}/key/h/{key:[0-9a-f]+}", as.createGetMapEntryHandler("hex", "std")).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}/key/s/{key:[0-9a-zA-Z-_]+}", as.createGetMapEntryHandler("str", "std")).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}/key/h/{key:[0-9a-f]+}/xjson", as.createGetMapEntryHandler("hex", "xjson")).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}/key/s/{key:[0-9a-zA-Z-_]+}/xjson", as.createGetMapEntryHandler("str", "xjson")).Methods("GET")

	// Delete a map entry
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/h/{key:[0-9a-f]+}", as.wrapClientHandler(deleteHexMapEntryHandler)).Methods("DELETE")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/s/{key:[0-9a-zA-Z-_]+}", as.wrapClientHandler(deleteStrMapEntryHandler)).Methods("DELETE")

	// Get STH
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}", as.wrapClientHandler(getMapRootHashHandler)).Methods("GET")

	//////////////
	// LOG OPERATIONS ON INPUT / OUTPUT OF MAP
	//////////////
	// Get a log entry
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/entry/{number:[0-9]+}", as.wrapLogFunction(logTypeMapMutation, getEntryHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/entry/{number:[0-9]+}", as.wrapLogFunction(logTypeMapTreeHead, getEntryHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/entry/{number:[0-9]+}/xjson", as.wrapLogFunction(logTypeMapMutation, getXJsonEntryHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/entry/{number:[0-9]+}/xjson", as.wrapLogFunction(logTypeMapTreeHead, getXJsonEntryHandler)).Methods("GET")

	// Get multiple entries, last is exclusive
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/entries/{first:[0-9]+}-{last:[0-9]+}", as.wrapLogFunction(logTypeMapMutation, getEntriesHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/entries/{first:[0-9]+}-{last:[0-9]+}", as.wrapLogFunction(logTypeMapTreeHead, getEntriesHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/entries/{first:[0-9]+}-{last:[0-9]+}/xjson", as.wrapLogFunction(logTypeMapMutation, getXJsonEntriesHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/entries/{first:[0-9]+}-{last:[0-9]+}/xjson/mutation", as.wrapLogFunction(logTypeMapMutation, getSpecialMutationsHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/entries/{first:[0-9]+}-{last:[0-9]+}/xjson", as.wrapLogFunction(logTypeMapTreeHead, getXJsonEntriesHandler)).Methods("GET")

	// Get STH
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/{treesize:(?:[0-9]+)|head}", as.wrapLogFunction(logTypeMapMutation, getSTHHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/tree/{treesize:(?:[0-9]+)|head}", as.wrapLogFunction(logTypeMapTreeHead, getSTHHandler)).Methods("GET")

	// Get inclusion proof by Hash
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/{treesize:[0-9]+}/inclusion/h/{hash:[0-9a-f]+}", as.wrapLogFunction(logTypeMapMutation, inclusionByHashProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/{treesize:[0-9]+}/inclusion/s/{strentry:[0-9a-zA-Z-_]+}", as.wrapLogFunction(logTypeMapMutation, inclusionByStringProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/{treesize:[0-9]+}/inclusion/{number:[0-9]+}", as.wrapLogFunction(logTypeMapMutation, inclusionByIndexProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/tree/{treesize:[0-9]+}/inclusion/h/{hash:[0-9a-f]+}", as.wrapLogFunction(logTypeMapTreeHead, inclusionByHashProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/tree/{treesize:[0-9]+}/inclusion/s/{strentry:[0-9a-zA-Z-_]+}", as.wrapLogFunction(logTypeMapTreeHead, inclusionByStringProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/tree/{treesize:[0-9]+}/inclusion/{number:[0-9]+}", as.wrapLogFunction(logTypeMapTreeHead, inclusionByIndexProofHandler)).Methods("GET")

	// Get consistency proof
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/{treesize:[0-9]+}/consistency/{oldsize:[0-9]+}", as.wrapLogFunction(logTypeMapMutation, getConsistencyProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/tree/{treesize:[0-9]+}/consistency/{oldsize:[0-9]+}", as.wrapLogFunction(logTypeMapTreeHead, getConsistencyProofHandler)).Methods("GET")

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

func (as *apiServer) wrapClientHandler(f func(vdbclient.Account, map[string]string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars, client := as.clientFromRequest(r)
		f(client, vars, w, r)
	}
}

func (as *apiServer) wrapLogFunction(logType int8, f func(vdbclient.VerifiableLog, map[string]string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	switch logType {
	case logTypeUser:
		return as.wrapClientHandler(func(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
			f(makeLogFromRequest(client, vars), vars, w, r)
		})
	case logTypeMapMutation:
		return as.wrapClientHandler(func(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
			f(makeMapFromRequest(client, vars).MutationLog(), vars, w, r)
		})
	case logTypeMapTreeHead:
		return as.wrapClientHandler(func(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
			f(makeMapFromRequest(client, vars).TreeHeadLog(), vars, w, r)
		})
	default:
		return nil
	}
}

func insertEntryHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)

	mtlHash, err := log.Add(&vdbclient.RawDataEntry{RawBytes: body})

	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&vdbclient.JSONAddEntryResponse{Hash: mtlHash.EntryLeafHash})
}

func insertRedactableXJsonEntryHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)

	mtlHash, err := log.Add(&vdbclient.RedactableJsonEntry{JsonBytes: body})

	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&vdbclient.JSONAddEntryResponse{Hash: mtlHash.EntryLeafHash})
}

func insertXJsonEntryHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)

	mtlHash, err := log.Add(&vdbclient.JsonEntry{JsonBytes: body})

	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&vdbclient.JSONAddEntryResponse{Hash: mtlHash.EntryLeafHash})
}

func getAPIKey(r *http.Request) string {
	headerParts := strings.Split(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if len(headerParts) == 2 {
		if headerParts[0] == "Key" {
			return headerParts[1]
		}
	}
	return ""
}

func handleError(err error, r *http.Request, w http.ResponseWriter) {
	switch err {
	case api.ErrNotAuthorized:
		w.WriteHeader(403)
	case api.ErrInvalidTreeRange:
		w.WriteHeader(400)
	case api.ErrInvalidJSON:
		w.WriteHeader(400)
	case api.ErrLogUnsafeForAccess:
		w.WriteHeader(404)
	case api.ErrNotFound:
		w.WriteHeader(404)
	case api.ErrLogAlreadyExists:
		w.WriteHeader(409)
	case api.ErrAlreadyNotActive: // no deleting a log twice thanks
		w.WriteHeader(409)
	default:
		log.Printf("Error: %s\n", err)
		w.WriteHeader(500)
	}
}

func makeLogFromRequest(client vdbclient.Account, vars map[string]string) vdbclient.VerifiableLog {
	return client.VerifiableLog(vars["log"])
}

func makeMapFromRequest(client vdbclient.Account, vars map[string]string) vdbclient.VerifiableMap {
	return client.VerifiableMap(vars["map"])
}

func (as *apiServer) clientFromRequest(r *http.Request) (map[string]string, vdbclient.Account) {
	vars := mux.Vars(r)
	return vars, as.clientFactory.Account(vars["account"], getAPIKey(r))
}

func listLogsHandler(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	logs, err := client.ListLogs()
	if err != nil {
		handleError(err, r, w)
		return
	}
	rv := make([]*vdbclient.JSONLogInfoResponse, len(logs))
	for idx, l := range logs {
		rv[idx] = &vdbclient.JSONLogInfoResponse{Name: l.Name()}
	}
	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&vdbclient.JSONLogListResponse{Items: rv})
}

func listMapsHandler(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	logs, err := client.ListMaps()
	if err != nil {
		handleError(err, r, w)
		return
	}
	rv := make([]*vdbclient.JSONMapInfoResponse, len(logs))
	for idx, l := range logs {
		rv[idx] = &vdbclient.JSONMapInfoResponse{Name: l.Name()}
	}
	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&vdbclient.JSONMapListResponse{Items: rv})
}

func (as *apiServer) createSetMapEntryHandler(keyFormat, valueFormat string) func(http.ResponseWriter, *http.Request) {
	return as.wrapClientHandler(func(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
		var k []byte
		var err error
		switch keyFormat {
		case "hex":
			k, err = hex.DecodeString(vars["key"])
			if err != nil {
				handleError(err, r, w)
				return
			}
		case "str":
			k = []byte(vars["key"])
		}

		body, _ := ioutil.ReadAll(r.Body)

		var ef vdbclient.UploadableEntry

		switch valueFormat {
		case "std":
			ef = &vdbclient.RawDataEntry{RawBytes: body}
		case "xjson":
			ef = &vdbclient.JsonEntry{JsonBytes: body}
		case "redactablejson":
			ef = &vdbclient.RedactableJsonEntry{JsonBytes: body}
		}

		prevLeafHashString := strings.TrimSpace(r.Header.Get("X-Previous-LeafHash"))
		var prevLeafHash []byte
		if len(prevLeafHashString) > 0 {
			prevLeafHash, err = hex.DecodeString(prevLeafHashString)
			if err != nil {
				handleError(err, r, w)
				return
			}
		}

		if k == nil || ef == nil {
			handleError(nil, r, w)
			return
		}

		vmap := makeMapFromRequest(client, vars)

		var mtlHash *vdbclient.AddEntryResponse
		if len(prevLeafHash) > 0 { // if we specified a previous leaf hash, then we meant to update
			mtlHash, err = vmap.Update(k, ef, &vdbclient.AddEntryResponse{EntryLeafHash: prevLeafHash})
		} else { // else we meant to set.
			mtlHash, err = vmap.Set(k, ef)
		}

		if err != nil {
			handleError(err, r, w)
			return
		}

		w.Header().Set("Content-Type", "text/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(&vdbclient.JSONAddEntryResponse{Hash: mtlHash.EntryLeafHash})
	})
}

func (as *apiServer) createGetMapEntryHandler(keyFormat, valueFormat string) func(http.ResponseWriter, *http.Request) {
	return as.wrapClientHandler(func(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
		vmap := makeMapFromRequest(client, vars)

		var k []byte
		var err error
		switch keyFormat {
		case "hex":
			k, err = hex.DecodeString(vars["key"])
			if err != nil {
				handleError(err, r, w)
				return
			}
		case "str":
			k = []byte(vars["key"])
		}

		var ef vdbclient.VerifiableEntryFactory

		switch valueFormat {
		case "std":
			ef = vdbclient.RawDataEntryFactory
		case "xjson":
			ef = vdbclient.RedactedJsonEntryFactory
		}

		if k == nil || ef == nil {
			handleError(nil, r, w)
			return
		}

		var treeSize int64
		if vars["treesize"] == "head" {
			treeSize = 0
		} else {
			ts, err := strconv.Atoi(vars["treesize"])
			if err != nil {
				w.WriteHeader(400)
				return
			}
			treeSize = int64(ts)
		}

		mapIncProof, err := vmap.Get(k, treeSize, ef)
		if err != nil {
			handleError(err, r, w)
			return
		}

		data, err := mapIncProof.Value.Data()
		if err != nil {
			handleError(err, r, w)
			return
		}

		w.Header().Set("X-Verified-TreeSize", strconv.Itoa(int(mapIncProof.TreeSize)))
		for i, p := range mapIncProof.AuditPath {
			if len(p) > 0 {
				w.Header().Add("X-Verified-Proof", strconv.Itoa(i)+"/"+hex.EncodeToString(p))
			}
		}

		w.Header().Set("Content-Type", http.DetectContentType(data))
		w.WriteHeader(200)
		w.Write(data)
	})
}

func getMapRootHashHandler(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	vmap := makeMapFromRequest(client, vars)
	var treeSize int64
	if vars["treesize"] == "head" {
		treeSize = 0
	} else {
		ts, err := strconv.Atoi(vars["treesize"])
		if err != nil {
			w.WriteHeader(400)
			return
		}
		treeSize = int64(ts)
	}

	mth, err := vmap.TreeHead(treeSize)
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&vdbclient.JSONMapTreeHeadResponse{
		MapHash: mth.RootHash,
		LogTreeHead: &vdbclient.JSONLogTreeHeadResponse{
			Hash:     mth.MutationLogTreeHead.RootHash,
			TreeSize: mth.MutationLogTreeHead.TreeSize,
		},
	})
}

func deleteMapEntryHandler(client vdbclient.Account, vars map[string]string, key []byte, w http.ResponseWriter, r *http.Request) {
	vmap := makeMapFromRequest(client, vars)
	mtlHash, err := vmap.Delete([]byte(key))

	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&vdbclient.JSONAddEntryResponse{Hash: mtlHash.EntryLeafHash})
}

func deleteStrMapEntryHandler(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	deleteMapEntryHandler(client, vars, []byte(vars["key"]), w, r)
}

func deleteHexMapEntryHandler(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	b, err := hex.DecodeString(vars["key"])
	if err != nil {
		handleError(err, r, w)
		return
	}
	deleteMapEntryHandler(client, vars, b, w, r)
}

func getXJsonEntryHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	baseGetEntryHandler(log, vars, vdbclient.RedactedJsonEntryFactory, w, r)
}

func getEntryHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	baseGetEntryHandler(log, vars, vdbclient.RawDataEntryFactory, w, r)
}

func baseGetEntryHandler(log vdbclient.VerifiableLog, vars map[string]string, ef vdbclient.VerifiableEntryFactory, w http.ResponseWriter, r *http.Request) {
	number, err := strconv.Atoi(vars["number"])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	data, err := log.Entry(int64(number), ef)
	if err != nil {
		handleError(err, r, w)
		return
	}

	val, err := data.Data()
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", http.DetectContentType(val))
	w.WriteHeader(200)
	w.Write(val)
}

func getSpecialMutationsHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	baseEntriesHandler(log, vars, vdbclient.RedactedJsonEntryFactory, w, r, true)
}

func getXJsonEntriesHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	baseEntriesHandler(log, vars, vdbclient.RedactedJsonEntryFactory, w, r, false)
}

func getEntriesHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	baseEntriesHandler(log, vars, vdbclient.RawDataEntryFactory, w, r, false)
}

func baseEntriesHandler(log vdbclient.VerifiableLog, vars map[string]string, ef vdbclient.VerifiableEntryFactory, w http.ResponseWriter, r *http.Request, doSpecialMutationJank bool) {
	first, err := strconv.Atoi(vars["first"])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	last, err := strconv.Atoi(vars["last"])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	rrv := make([]*vdbclient.JSONGetEntryResponse, 0, last-first)
	i := first
	/* TODO, proper context and cancel on error below */
	for d := range log.Entries(context.TODO(), int64(first), int64(last), ef) {
		val, err := d.Data()
		if err != nil {
			w.WriteHeader(500)
			return
		}
		rrv = append(rrv, &vdbclient.JSONGetEntryResponse{Number: int64(i + first), Data: val})
		i++
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&vdbclient.JSONGetEntriesResponse{
		Entries: rrv,
	})
}

func inclusionByIndexProofHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	treeSize, err := strconv.Atoi(vars["treesize"])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	number, err := strconv.Atoi(vars["number"])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	mip, err := log.InclusionProofByIndex(int64(treeSize), int64(number))
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&vdbclient.JSONInclusionProofResponse{
		Number:   mip.LeafIndex,
		TreeSize: mip.TreeSize,
		Proof:    mip.AuditPath,
	})
}

func leafHash(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(b)
	return h.Sum(nil)
}

func inclusionByStringProofHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	inclusionProofHandler(leafHash([]byte(vars["strentry"])), log, vars, w, r)
}

func inclusionByHashProofHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	mtlHash, err := hex.DecodeString(vars["hash"])
	if err != nil {
		handleError(err, r, w)
		return
	}
	inclusionProofHandler(mtlHash, log, vars, w, r)
}

func createMapHandler(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	vmap := makeMapFromRequest(client, vars)

	err := vmap.Create()
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.WriteHeader(200)
}

func deleteMapHandler(client vdbclient.Account, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	vmap := makeMapFromRequest(client, vars)

	err := vmap.Destroy()
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.WriteHeader(200)
}

func createLogHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	err := log.Create()
	if err != nil {
		handleError(err, r, w)
		return
	}
	w.WriteHeader(200)
}

func deleteLogHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	err := log.Destroy()
	if err != nil {
		handleError(err, r, w)
		return
	}
	w.WriteHeader(200)
}

func inclusionProofHandler(mtlHash []byte, flog vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	treeSize, err := strconv.Atoi(vars["treesize"])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	mip, err := flog.InclusionProof(int64(treeSize), &vdbclient.AddEntryResponse{EntryLeafHash: mtlHash})
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&vdbclient.JSONInclusionProofResponse{
		Number:   mip.LeafIndex,
		TreeSize: mip.TreeSize,
		Proof:    mip.AuditPath,
	})
}

func getConsistencyProofHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	treeSize, err := strconv.Atoi(vars["treesize"])
	if err != nil {
		w.WriteHeader(400)
		return
	}
	oldSize, err := strconv.Atoi(vars["oldsize"])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	cproof, err := log.ConsistencyProof(int64(oldSize), int64(treeSize))
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&vdbclient.JSONConsistencyProofResponse{
		First:  cproof.FirstSize,
		Second: cproof.SecondSize,
		Proof:  cproof.AuditPath,
	})
}

func getSTHHandler(log vdbclient.VerifiableLog, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	var treeSize int64
	if vars["treesize"] == "head" {
		treeSize = 0
	} else {
		ts, err := strconv.Atoi(vars["treesize"])
		if err != nil {
			w.WriteHeader(400)
			return
		}
		treeSize = int64(ts)
	}

	sth, err := log.TreeHead(treeSize)
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&vdbclient.JSONLogTreeHeadResponse{
		TreeSize: sth.TreeSize,
		Hash:     sth.RootHash,
	})
}
