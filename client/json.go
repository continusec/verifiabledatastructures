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
	// Timestamp is needed to ensure that the mutation operation is unique (except in pessimal cases).
	// Otherise the mutation log will cleverly choose not to add it, and it wil never apply.
	// time.Time marshals to RFC3339 string.
	Timestamp time.Time `json:"timestamp,omitempty"`

	// One of "set", "delete", "update"
	Action string `json:"action,omitempty"`
	Key    []byte `json:"key,omitempty"`

	// Used for "set" and "update". This is the value that is used to calculate the leaf hash, so for JSON this is the objecthash.
	ValueLeafInput []byte `json:"value_leaf_input,omitempty"`

	// Used for "set" and "update". This is the value that is used support the leaf input, so for JSON this is the original JSON.
	ValueExtraData []byte `json:"value_extra_data,omitempty"`

	// Used for "update". This is the previous leaf hash (not value).
	PreviousLeafHash []byte `json:"previous,omitempty"`
}
