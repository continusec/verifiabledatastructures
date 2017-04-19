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
	"sync"

	"github.com/golang/protobuf/proto"
)

// TransientHashMapStorage gives a service that locks terrible, and does it all in memory
type TransientHashMapStorage struct {
	dbLock sync.RWMutex
	data   map[string]map[string][]byte
}

// ExecuteReadOnly executes a read only query
func (bbs *TransientHashMapStorage) ExecuteReadOnly(namespace []byte, f func(db KeyReader) error) error {
	key := hex.EncodeToString(namespace)

	bbs.dbLock.RLock()
	defer bbs.dbLock.RUnlock()

	var db map[string][]byte
	if bbs.data != nil {
		x, ok := bbs.data[key]
		if ok {
			db = x
		}
	}

	return f(&memoryThing{Data: db})
}

// ExecuteUpdate executes an update query
func (bbs *TransientHashMapStorage) ExecuteUpdate(namespace []byte, f func(db KeyWriter) error) error {
	key := hex.EncodeToString(namespace)

	bbs.dbLock.Lock()
	defer bbs.dbLock.Unlock()

	if bbs.data == nil {
		bbs.data = make(map[string]map[string][]byte)
	}
	db, ok := bbs.data[key]
	if !ok {
		db = make(map[string][]byte)
		bbs.data[key] = db
	}
	return f(&memoryThing{Data: db})
}

type memoryThing struct {
	Data map[string][]byte
}

func (db *memoryThing) Get(bucket, key []byte, value proto.Message) error {
	if db.Data == nil {
		return ErrNoSuchKey
	}
	actKey := string(bucket) + "|" + string(key) // TODO, fix to something guaranteed to be unique
	rv, ok := db.Data[actKey]
	if !ok { // as distinct from 0 length
		return ErrNoSuchKey
	}
	return proto.Unmarshal(rv, value)
}

func (db *memoryThing) Set(bucket, key []byte, value proto.Message) error {
	if db.Data == nil {
		return ErrNotImplemented
	}
	actKey := string(bucket) + "|" + string(key) // TODO, fix to something guaranteed to be unique
	if value == nil {
		delete(db.Data, actKey)
		return nil
	}
	bb, err := proto.Marshal(value)
	if err != nil {
		return err
	}
	db.Data[actKey] = bb
	return nil
}
