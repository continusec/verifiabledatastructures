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

package badger

import (
	"encoding/hex"
	"path/filepath"
	"sync"

	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/verifiable"
	"github.com/dgraph-io/badger"
	"github.com/golang/protobuf/proto"
)

// Storage gives a service that persists to a Badger DB file.
type Storage struct {
	// Path is a path to a directory where we will create files, one per user Map / user Log.
	Path string

	dbLock sync.RWMutex
	dbs    map[string]*badger.DB
}

// Close calls the underlying Close method on the BoltDBs which releases file locks.
func (bbs *Storage) Close() {
	bbs.dbLock.Lock()
	defer bbs.dbLock.Unlock()

	for _, db := range bbs.dbs {
		// Ignore any errors
		db.Close()
	}
}

// Returns nil if not found
func (bbs *Storage) getDB(key string) *badger.DB {
	bbs.dbLock.RLock()
	defer bbs.dbLock.RUnlock()

	if bbs.dbs == nil {
		return nil
	}

	rv, ok := bbs.dbs[key]
	if ok {
		return rv
	}

	return nil
}

// getOrCreateDB gets and/or creates DB
func (bbs *Storage) getOrCreateDB(ns []byte) (*badger.DB, error) {
	key := hex.EncodeToString(ns)

	// First try with simple read lock
	rv := bbs.getDB(key)
	if rv != nil {
		return rv, nil
	}

	// Else, get a write lock and load it up
	bbs.dbLock.Lock()
	defer bbs.dbLock.Unlock()

	if bbs.dbs == nil {
		bbs.dbs = make(map[string]*badger.DB)
	}

	// Check again, as may have been added since last
	rv, ok := bbs.dbs[key]
	if ok {
		return rv, nil
	}

	// Get or create on disk
	db, err := badger.Open(badger.DefaultOptions(filepath.Join(bbs.Path, key)))
	if err != nil {
		return nil, err
	}
	bbs.dbs[key] = db

	return db, nil
}

// ExecuteReadOnly executes a read only query
func (bbs *Storage) ExecuteReadOnly(ctx context.Context, namespace []byte, f func(ctx context.Context, db verifiable.KeyReader) error) error {
	db, err := bbs.getOrCreateDB(namespace)
	if err != nil {
		return err
	}
	return db.View(func(tx *badger.Txn) error {
		return f(ctx, &badgerReaderWriter{Tx: tx})
	})
}

// ExecuteUpdate executes an update query
func (bbs *Storage) ExecuteUpdate(ctx context.Context, namespace []byte, f func(ctx context.Context, db verifiable.KeyWriter) error) error {
	db, err := bbs.getOrCreateDB(namespace)
	if err != nil {
		return err
	}
	return db.Update(func(tx *badger.Txn) error {
		return f(ctx, &badgerReaderWriter{Tx: tx})
	})
}

type badgerReaderWriter struct {
	Tx *badger.Txn
}

func (db *badgerReaderWriter) Get(ctx context.Context, key []byte, value proto.Message) error {
	item, err := db.Tx.Get(key)
	if err != nil {
		return verifiable.ErrNoSuchKey
	}
	return item.Value(func(bb []byte) error {
		return proto.Unmarshal(bb, value)
	})
}

func (db *badgerReaderWriter) Set(ctx context.Context, key []byte, value proto.Message) error {
	if value == nil {
		return db.Tx.Delete(key)
	}
	bb, err := proto.Marshal(value)
	if err != nil {
		return err
	}
	return db.Tx.Set(key, bb)
}
