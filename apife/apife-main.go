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
	"log"

	"github.com/continusec/vds-server/api"

	"bytes"
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

type apiServer struct {
	clientFactory api.ClientFactory
}

// CreateHandler creates handlers for the API
func CreateHandler(clif api.ClientFactory) http.Handler {
	as := &apiServer{clientFactory: clif}

	r := mux.NewRouter()

	// Create a log
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}", as.wrapLogFunction(api.LogTypeUser, createLogHandler)).Methods("PUT")

	// Delete a log
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}", as.wrapLogFunction(api.LogTypeUser, deleteLogHandler)).Methods("DELETE")

	// List logs
	r.HandleFunc("/v1/account/{account:[0-9]+}/logs", as.wrapClientHandler(listLogsHandler)).Methods("GET")

	// Insert a log entry
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry", as.wrapLogFunction(api.LogTypeUser, insertEntryHandler)).Methods("POST")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/xjson", as.wrapLogFunction(api.LogTypeUser, insertXJsonEntryHandler)).Methods("POST")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/xjson/redactable", as.wrapLogFunction(api.LogTypeUser, insertRedactableXJsonEntryHandler)).Methods("POST")

	// Get a log entry
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/{number:[0-9]+}", as.wrapLogFunction(api.LogTypeUser, getEntryHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/{number:[0-9]+}/xjson", as.wrapLogFunction(api.LogTypeUser, getXJsonEntryHandler)).Methods("GET")

	// Get multiple entries, last is exclusive
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entries/{first:[0-9]+}-{last:[0-9]+}", as.wrapLogFunction(api.LogTypeUser, getEntriesHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entries/{first:[0-9]+}-{last:[0-9]+}/xjson", as.wrapLogFunction(api.LogTypeUser, getXJsonEntriesHandler)).Methods("GET")

	// Get STH
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:(?:[0-9]+)|head}", as.wrapLogFunction(api.LogTypeUser, getSTHHandler)).Methods("GET")

	// Get inclusion proof by Hash
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/inclusion/h/{hash:[0-9a-f]+}", as.wrapLogFunction(api.LogTypeUser, inclusionByHashProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/inclusion/s/{strentry:[0-9a-zA-Z-_]+}", as.wrapLogFunction(api.LogTypeUser, inclusionByStringProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/inclusion/{number:[0-9]+}", as.wrapLogFunction(api.LogTypeUser, inclusionByIndexProofHandler)).Methods("GET")

	// Get consistency proof
	r.HandleFunc("/v1/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/consistency/{oldsize:[0-9]+}", as.wrapLogFunction(api.LogTypeUser, getConsistencyProofHandler)).Methods("GET")

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
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/entry/{number:[0-9]+}", as.wrapLogFunction(api.LogTypeMapMutation, getEntryHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/entry/{number:[0-9]+}", as.wrapLogFunction(api.LogTypeMapTreeHead, getEntryHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/entry/{number:[0-9]+}/xjson", as.wrapLogFunction(api.LogTypeMapMutation, getXJsonEntryHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/entry/{number:[0-9]+}/xjson", as.wrapLogFunction(api.LogTypeMapTreeHead, getXJsonEntryHandler)).Methods("GET")

	// Get multiple entries, last is exclusive
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/entries/{first:[0-9]+}-{last:[0-9]+}", as.wrapLogFunction(api.LogTypeMapMutation, getEntriesHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/entries/{first:[0-9]+}-{last:[0-9]+}", as.wrapLogFunction(api.LogTypeMapTreeHead, getEntriesHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/entries/{first:[0-9]+}-{last:[0-9]+}/xjson", as.wrapLogFunction(api.LogTypeMapMutation, getXJsonEntriesHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/entries/{first:[0-9]+}-{last:[0-9]+}/xjson/mutation", as.wrapLogFunction(api.LogTypeMapMutation, getSpecialMutationsHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/entries/{first:[0-9]+}-{last:[0-9]+}/xjson", as.wrapLogFunction(api.LogTypeMapTreeHead, getXJsonEntriesHandler)).Methods("GET")

	// Get STH
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/{treesize:(?:[0-9]+)|head}", as.wrapLogFunction(api.LogTypeMapMutation, getSTHHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/tree/{treesize:(?:[0-9]+)|head}", as.wrapLogFunction(api.LogTypeMapTreeHead, getSTHHandler)).Methods("GET")

	// Get inclusion proof by Hash
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/{treesize:[0-9]+}/inclusion/h/{hash:[0-9a-f]+}", as.wrapLogFunction(api.LogTypeMapMutation, inclusionByHashProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/{treesize:[0-9]+}/inclusion/s/{strentry:[0-9a-zA-Z-_]+}", as.wrapLogFunction(api.LogTypeMapMutation, inclusionByStringProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/{treesize:[0-9]+}/inclusion/{number:[0-9]+}", as.wrapLogFunction(api.LogTypeMapMutation, inclusionByIndexProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/tree/{treesize:[0-9]+}/inclusion/h/{hash:[0-9a-f]+}", as.wrapLogFunction(api.LogTypeMapTreeHead, inclusionByHashProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/tree/{treesize:[0-9]+}/inclusion/s/{strentry:[0-9a-zA-Z-_]+}", as.wrapLogFunction(api.LogTypeMapTreeHead, inclusionByStringProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/tree/{treesize:[0-9]+}/inclusion/{number:[0-9]+}", as.wrapLogFunction(api.LogTypeMapTreeHead, inclusionByIndexProofHandler)).Methods("GET")

	// Get consistency proof
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/{treesize:[0-9]+}/consistency/{oldsize:[0-9]+}", as.wrapLogFunction(api.LogTypeMapMutation, getConsistencyProofHandler)).Methods("GET")
	r.HandleFunc("/v1/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/tree/{treesize:[0-9]+}/consistency/{oldsize:[0-9]+}", as.wrapLogFunction(api.LogTypeMapTreeHead, getConsistencyProofHandler)).Methods("GET")

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

func (as *apiServer) wrapClientHandler(f func(api.VerifiableDataStructuresService, map[string]string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars, client, err := as.clientFromRequest(r)
		if err != nil {
			handleError(err, r, w)
			return
		}
		f(client, vars, w, r)
	}
}

func (as *apiServer) wrapLogFunction(logType int8, f func(api.Log, map[string]string, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	switch logType {
	case api.LogTypeUser:
		return as.wrapClientHandler(func(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
			log, err := makeLogFromRequest(client, vars, api.LogTypeUser)
			if err != nil {
				handleError(err, r, w)
				return
			}
			f(log, vars, w, r)
		})
	case api.LogTypeMapMutation:
		return as.wrapClientHandler(func(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
			vmap, err := makeMapFromRequest(client, vars)
			if err != nil {
				handleError(err, r, w)
				return
			}
			ml, err := vmap.MutationLog()
			if err != nil {
				handleError(err, r, w)
				return
			}
			f(ml, vars, w, r)
		})
	case api.LogTypeMapTreeHead:
		return as.wrapClientHandler(func(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
			vmap, err := makeMapFromRequest(client, vars)
			if err != nil {
				handleError(err, r, w)
				return
			}
			thl, err := vmap.TreeHeadLog()
			if err != nil {
				handleError(err, r, w)
				return
			}
			f(thl, vars, w, r)
		})
	default:
		return nil
	}
}

type insertEntryResponse struct {
	Hash []byte `json:"leaf_hash"`
}

type consistencyResponse struct {
	First  int64    `json:"first_tree_size"`
	Second int64    `json:"second_tree_size"`
	Proof  [][]byte `json:"proof"`
}

type inclusionProofResponse struct {
	Number   int64    `json:"leaf_index"`
	TreeSize int64    `json:"tree_size"`
	Proof    [][]byte `json:"proof"`
}

type getEntryResponse struct {
	Number int64  `json:"leaf_index"`
	Data   []byte `json:"leaf_data"`
}

type mutationWithJSONEntryResponse struct {
	MutationLogEntry []byte `json:"mutation_log_entry"`
	OHInput          []byte `json:"objecthash_input"`
}

type getEntriesResponse struct {
	Entries []*getEntryResponse `json:"entries"`
}

type mapValueResponse struct {
	Value    []byte   `json:"value"`
	TreeSize int64    `json:"tree_size"`
	Proof    [][]byte `json:"proof"`
}

func insertEntryHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)

	mtlHash, err := log.Add(&api.RawEntryFormat{Data: body})

	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&insertEntryResponse{Hash: mtlHash})
}

func insertRedactableXJsonEntryHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)

	mtlHash, err := log.Add(&api.ObjectHashEntryFormat{Data: body, Redactable: true})

	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&insertEntryResponse{Hash: mtlHash})
}

func insertXJsonEntryHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)

	mtlHash, err := log.Add(&api.ObjectHashEntryFormat{Data: body})

	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&insertEntryResponse{Hash: mtlHash})
}

func getAuthorizationContext(r *http.Request) *api.AuthorizationContext {
	var rv api.AuthorizationContext

	headerParts := strings.Split(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if len(headerParts) == 2 {
		if headerParts[0] == "Key" {
			rv.APIKey = headerParts[1]
		}
	}

	return &rv
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

func resolveAccountID(account string) (int64, error) {
	number, err := strconv.Atoi(account)
	if err != nil {
		return -1, err
	}
	return int64(number), nil
}

func makeLogFromRequest(client api.VerifiableDataStructuresService, vars map[string]string, logType int8) (api.Log, error) {
	return client.GetLog(vars["log"], logType)
}

func makeMapFromRequest(client api.VerifiableDataStructuresService, vars map[string]string) (api.Map, error) {
	return client.GetMap(vars["map"])
}

type objectResponse struct {
	Name string `json:"name"`
}

type objectListResponse struct {
	Items []*objectResponse `json:"results"`
}

func (as *apiServer) clientFromRequest(r *http.Request) (map[string]string, api.VerifiableDataStructuresService, error) {
	vars := mux.Vars(r)
	accID, err := resolveAccountID(vars["account"])
	if err != nil {
		return nil, nil, err
	}
	client, err := as.clientFactory.CreateClient(accID, getAuthorizationContext(r))
	if err != nil {
		return nil, nil, err
	}
	return vars, client, nil
}

func listLogsHandler(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	logs, err := client.ListLogs()
	if err != nil {
		handleError(err, r, w)
		return
	}
	rv := make([]*objectResponse, len(logs))
	for idx, l := range logs {
		rv[idx] = &objectResponse{Name: l.Name()}
	}
	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&objectListResponse{Items: rv})
}

func listMapsHandler(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	logs, err := client.ListMaps()
	if err != nil {
		handleError(err, r, w)
		return
	}
	rv := make([]*objectResponse, len(logs))
	for idx, l := range logs {
		rv[idx] = &objectResponse{Name: l.Name()}
	}
	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&objectListResponse{Items: rv})
}

func (as *apiServer) createSetMapEntryHandler(keyFormat, valueFormat string) func(http.ResponseWriter, *http.Request) {
	return as.wrapClientHandler(func(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
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

		var ef api.EntryFormat

		switch valueFormat {
		case "std":
			ef = &api.RawEntryFormat{Data: body}
		case "xjson":
			ef = &api.ObjectHashEntryFormat{Data: body}
		case "redactablejson":
			ef = &api.ObjectHashEntryFormat{Data: body, Redactable: true}
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

		vmap, err := makeMapFromRequest(client, vars)
		if err != nil {
			handleError(err, r, w)
			return
		}

		var mtlHash []byte
		if len(prevLeafHash) > 0 { // if we specified a previous leaf hash, then we meant to update
			mtlHash, err = vmap.Update(k, prevLeafHash, ef)
		} else { // else we meant to set.
			mtlHash, err = vmap.Set(k, ef)
		}

		if err != nil {
			handleError(err, r, w)
			return
		}

		w.Header().Set("Content-Type", "text/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(&insertEntryResponse{Hash: mtlHash})
	})
}

func (as *apiServer) createGetMapEntryHandler(keyFormat, valueFormat string) func(http.ResponseWriter, *http.Request) {
	return as.wrapClientHandler(func(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
		vmap, err := makeMapFromRequest(client, vars)
		if err != nil {
			handleError(err, r, w)
			return
		}

		var k []byte
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

		var ef api.EntryFormat

		switch valueFormat {
		case "std":
			ef = &api.RawEntryFormat{}
		case "xjson":
			ff, err := vmap.GetFilterField()
			if err != nil {
				handleError(err, r, w)
				return
			}
			ef = &api.ObjectHashEntryFormat{Filter: ff}
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

		data, proof, treeSize, err := vmap.Get(k, ef, treeSize)
		if err != nil {
			handleError(err, r, w)
			return
		}

		w.Header().Set("X-Verified-TreeSize", strconv.Itoa(int(treeSize)))
		for i, p := range proof {
			if len(p) > 0 {
				w.Header().Add("X-Verified-Proof", strconv.Itoa(i)+"/"+hex.EncodeToString(p))
			}
		}

		w.Header().Set("Content-Type", http.DetectContentType(data))
		w.WriteHeader(200)
		w.Write(data)
	})
}

func getMapRootHashHandler(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	vmap, err := makeMapFromRequest(client, vars)
	if err != nil {
		handleError(err, r, w)
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

	treeSize, hash, err := vmap.GetTreeHash(treeSize)
	if err != nil {
		handleError(err, r, w)
		return
	}

	var mutLogHash []byte
	if treeSize > 0 {
		ml, err := vmap.MutationLog()
		if err != nil {
			handleError(err, r, w)
			return
		}
		_, mutLogHash, err = ml.GetTreeHash(treeSize)
		switch err {
		case nil:
			// all good
		case api.ErrNotAuthorized:
			// all good too, perfectly fine not to be allowed to see
		default:
			handleError(err, r, w)
			return
		}
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	resp := &api.MapHashResponse{
		MapHash: hash,
		LogSTH:  &api.STHResponse{TreeSize: treeSize, Hash: mutLogHash},
	}
	enc := json.NewEncoder(w)
	enc.Encode(resp)
}

func deleteMapEntryHandler(client api.VerifiableDataStructuresService, vars map[string]string, key []byte, w http.ResponseWriter, r *http.Request) {
	vmap, err := makeMapFromRequest(client, vars)
	if err != nil {
		handleError(err, r, w)
		return
	}

	mtlHash, err := vmap.Delete([]byte(key))

	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(&insertEntryResponse{Hash: mtlHash})
}

func deleteStrMapEntryHandler(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	deleteMapEntryHandler(client, vars, []byte(vars["key"]), w, r)
}

func deleteHexMapEntryHandler(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	b, err := hex.DecodeString(vars["key"])
	if err != nil {
		handleError(err, r, w)
		return
	}
	deleteMapEntryHandler(client, vars, b, w, r)
}

func getXJsonEntryHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	baseGetEntryHandler(log, vars, &api.ObjectHashEntryFormat{Filter: log.GetFilterField()}, w, r)
}

func getEntryHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	baseGetEntryHandler(log, vars, &api.RawEntryFormat{}, w, r)
}

func baseGetEntryHandler(log api.Log, vars map[string]string, ef api.EntryFormat, w http.ResponseWriter, r *http.Request) {
	number, err := strconv.Atoi(vars["number"])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	data, err := log.GetEntry(int64(number), ef)
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", http.DetectContentType(data))
	w.WriteHeader(200)
	w.Write(data)
}

func getSpecialMutationsHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	baseEntriesHandler(log, vars, &api.ObjectHashEntryFormat{Filter: log.GetFilterField()}, w, r, true)
}

func getXJsonEntriesHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	baseEntriesHandler(log, vars, &api.ObjectHashEntryFormat{Filter: log.GetFilterField()}, w, r, false)
}

func getEntriesHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	baseEntriesHandler(log, vars, &api.RawEntryFormat{}, w, r, false)
}

func baseEntriesHandler(log api.Log, vars map[string]string, ef api.EntryFormat, w http.ResponseWriter, r *http.Request, doSpecialMutationJank bool) {
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

	data, err := log.GetEntries(int64(first), int64(last), ef)
	if err != nil {
		handleError(err, r, w)
		return
	}

	rrv := make([]*getEntryResponse, 0, len(data))
	for i, d := range data {
		if d == nil {
			d = make([]byte, 0)
		}
		rrv = append(rrv, &getEntryResponse{Number: int64(i + first), Data: d})
	}

	// This is pretty terrible
	if doSpecialMutationJank {
		hashesNeeded := make([][]byte, 0)
		for _, d := range data {
			var mut api.MapMutation
			err = json.NewDecoder(bytes.NewReader(d)).Decode(&mut)
			if err != nil {
				handleError(err, r, w)
				return
			}

			// Fail if this doesn't look and smell like an object hash.
			// e.g. if a map element has been set as a plain value, not object hash
			if len(mut.Value) != 32 {
				w.WriteHeader(400)
				return
			}

			// Otherwise, let's assume that any 32 byte value is an object hash.
			// If it isn't, then we'll likely fail inside of GetMultiBlob

			h := sha256.New()
			h.Write([]byte{0})
			h.Write(mut.Value)
			dataHash := h.Sum(nil)

			hashesNeeded = append(hashesNeeded, dataHash[:])
		}

		extraVals, err := log.GetMultiBlob(hashesNeeded, ef)
		if err != nil {
			handleError(err, r, w)
			return
		}

		// Now wrap the leaf_input
		for i, ev := range extraVals {
			b := &bytes.Buffer{}
			err = json.NewEncoder(b).Encode(&mutationWithJSONEntryResponse{
				MutationLogEntry: rrv[i].Data,
				OHInput:          ev,
			})
			if err != nil {
				handleError(err, r, w)
				return
			}
			rrv[i].Data = b.Bytes()
		}

		// Truncate if needed, e.g. we couldn't find everything
		rrv = rrv[:len(extraVals)]
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&getEntriesResponse{
		Entries: rrv,
	})
}

func inclusionByIndexProofHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
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

	n2, actTreeSize, hashes, err := log.GetInclusionProofByNumber(int64(number), int64(treeSize))
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&inclusionProofResponse{
		Number:   int64(n2),
		TreeSize: actTreeSize,
		Proof:    hashes,
	})
}

func leafHash(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(b)
	return h.Sum(nil)
}

func inclusionByStringProofHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	inclusionProofHandler(leafHash([]byte(vars["strentry"])), log, vars, w, r)
}

func inclusionByHashProofHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	mtlHash, err := hex.DecodeString(vars["hash"])
	if err != nil {
		handleError(err, r, w)
		return
	}
	inclusionProofHandler(mtlHash, log, vars, w, r)
}

func createMapHandler(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	vmap, err := makeMapFromRequest(client, vars)
	if err != nil {
		handleError(err, r, w)
		return
	}

	err = vmap.Create()
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.WriteHeader(200)
}

func deleteMapHandler(client api.VerifiableDataStructuresService, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	vmap, err := makeMapFromRequest(client, vars)
	if err != nil {
		handleError(err, r, w)
		return
	}

	err = vmap.DeleteMap()
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.WriteHeader(200)
}

func createLogHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	err := log.Create()
	if err != nil {
		handleError(err, r, w)
		return
	}
	w.WriteHeader(200)
}

func deleteLogHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	err := log.Delete()
	if err != nil {
		handleError(err, r, w)
		return
	}
	w.WriteHeader(200)
}

func inclusionProofHandler(mtlHash []byte, flog api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
	treeSize, err := strconv.Atoi(vars["treesize"])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	number, actTreeSize, hashes, err := flog.GetInclusionProof(mtlHash, int64(treeSize))
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&inclusionProofResponse{
		Number:   number,
		TreeSize: actTreeSize,
		Proof:    hashes,
	})
}

func getConsistencyProofHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
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

	actTreeSize, hashes, err := log.GetConsistencyProof(int64(oldSize), int64(treeSize))
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(consistencyResponse{
		First:  int64(oldSize),
		Second: actTreeSize,
		Proof:  hashes,
	})
}

func getSTHHandler(log api.Log, vars map[string]string, w http.ResponseWriter, r *http.Request) {
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

	treeSize, hash, err := log.GetTreeHash(treeSize)
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", "text/json")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&api.STHResponse{
		TreeSize: treeSize,
		Hash:     hash,
	})
}
