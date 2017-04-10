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

import "time"

type JSONAddEntryResponse struct {
	Number int64  `json:"leaf_index"`
	Hash   []byte `json:"leaf_hash"`
}

type JSONLogTreeHeadResponse struct {
	TreeSize int64  `json:"tree_size"`
	Hash     []byte `json:"tree_hash"`
}

type JSONConsistencyProofResponse struct {
	First  int64    `json:"first_tree_size"`
	Second int64    `json:"second_tree_size"`
	Proof  [][]byte `json:"proof"`
}

type JSONGetEntryResponse struct {
	Number int64  `json:"leaf_index"`
	Hash   []byte `json:"leaf_hash"`
	Data   []byte `json:"leaf_data"`
}

type JSONGetEntriesResponse struct {
	Entries []*JSONGetEntryResponse `json:"entries"`
}

type JSONInclusionProofResponse struct {
	Number   int64    `json:"leaf_index"`
	TreeSize int64    `json:"tree_size"`
	Proof    [][]byte `json:"proof"`
}

type JSONMapTreeHeadResponse struct {
	MapHash     []byte                   `json:"map_hash"`
	LogTreeHead *JSONLogTreeHeadResponse `json:"mutation_log"`
}

// JSONMapMutationEntry represents an entry in the Mutation Log for a map
type JSONMapMutationEntry struct {
	// When the mutation entry was generated
	Timestamp time.Time `json:"timestamp"`

	// One of "set", "delete", "update"
	Action string `json:"action"`

	// Which key did this affect
	Key []byte `json:"key"`

	// Used for "set" and "update". This is the value that is used to calculated the leaf hash, so for Json this is the objecthash.
	Value []byte `json:"value"`

	// Used for "update". This is the previous leaf hash (not value).
	PreviousLeafHash []byte `json:"previous"`
}

type JSONLogListResponse struct {
	Items []*JSONLogInfoResponse `json:"results"`
}

type JSONMapListResponse struct {
	Items []*JSONMapInfoResponse `json:"results"`
}

// JSONMapInfoResponse represents metadata about a map
type JSONMapInfoResponse struct {
	// Name is the name of the map
	Name string `json:"name"`
}

// JSONLogInfoResponse represents metadata about a log
type JSONLogInfoResponse struct {
	// Name is the name of the log
	Name string `json:"name"`
}
