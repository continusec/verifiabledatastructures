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

package api

import (
	"errors"
	"time"
)

const (
	LogTypeNoFilter    = int8(-1)
	LogTypeUser        = int8(0)
	LogTypeMapMutation = int8(1)
	LogTypeMapTreeHead = int8(2)
)

var (
	ErrInvalidJSON                    = errors.New("ErrInvalidJSON")
	ErrNotFound                       = errors.New("ErrNotFound")
	ErrAlreadyNotActive               = errors.New("ErrAlreadyNotActive")
	ErrNotAuthorized                  = errors.New("Unauthorized request")
	ErrInvalidTreeRange               = errors.New("Invalid index")
	ErrSubTreeHashShouldBeForPow2Only = errors.New("Subtree hash is used for powers of 2 only")
	ErrNotReadyYet                    = errors.New("Tree hashes still calculating")
	ErrLogAlreadyExists               = errors.New("ErrLogAlreadyExists")
	ErrLogUnsafeForAccess             = errors.New("ErrLogUnsafeForAccess")
)

type EntryFormat interface {
	BytesForLeafHash() ([]byte, error)
	BytesToStoreOff() ([]byte, error)
	RetrieveBytes(DatastoreBlobEntry) ([]byte, error)
}

type DatastoreBlobEntry interface {
	Data() ([]byte, error)
}

type AuthorizationContext struct {
	APIKey string
}

// STHResponse is used in the Tree Head Log and thus this is pretty frozen
type STHResponse struct {
	TreeSize int64  `json:"tree_size"`
	Hash     []byte `json:"tree_hash"`
}

// MapHashResponse is used in the Tree Head Log and thus this is pretty frozen
type MapHashResponse struct {
	MapHash []byte       `json:"map_hash"`
	LogSTH  *STHResponse `json:"mutation_log"`
}

// MapMutation is used in the Mutation Log and thus this is pretty frozen
type MapMutation struct {
	Timestamp time.Time `json:"timestamp,omitempty"`

	// One of "set", "delete", "update"
	Action string `json:"action,omitempty"`
	Key    []byte `json:"key,omitempty"`

	// Used for "set" and "update". This is the value that is used to calculate the leaf hash, so for JSON this is the objecthash.
	Value []byte `json:"value,omitempty"`

	// Used for "update". This is the previous leaf hash (not value).
	PreviousLeafHash []byte `json:"previous,omitempty"`
}

type Log interface {
	Add(EntryFormat) ([]byte, error)
	Name() string
	GetTreeHash(treesize int64) (int64, []byte, error)
	GetFilterField() string
	GetEntry(idx int64, ef EntryFormat) ([]byte, error)
	GetEntries(first, lastt int64, ef EntryFormat) ([][]byte, error)
	GetMultiBlob(hashesNeeded [][]byte, ef EntryFormat) ([][]byte, error)
	GetInclusionProofByNumber(idx, treesize int64) (int64, int64, [][]byte, error)
	GetInclusionProof(mtlHash []byte, treesize int64) (int64, int64, [][]byte, error)
	Create() error
	Delete() error
	GetConsistencyProof(size1, size2 int64) (int64, [][]byte, error)
}

type Map interface {
	MutationLog() (Log, error)
	TreeHeadLog() (Log, error)
	Name() string
	Update(key, prevLeafHash []byte, entry EntryFormat) ([]byte, error)
	Set(key []byte, entry EntryFormat) ([]byte, error)
	Delete(key []byte) ([]byte, error)
	GetFilterField() (string, error)
	Get(key []byte, ef EntryFormat, treesize int64) ([]byte, [][]byte, int64, error)
	GetTreeHash(treesize int64) (int64, []byte, error)
	Create() error
	DeleteMap() error
}

type VerifiableDataStructuresService interface {
	GetLog(name string, logType int8) (Log, error)
	GetMap(name string) (Map, error)
	ListLogs() ([]Log, error)
	ListMaps() ([]Map, error)
}

type ClientFactory interface {
	CreateClient(account int64, auth *AuthorizationContext) (VerifiableDataStructuresService, error)
}
