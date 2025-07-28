/*

Copyright 2019 Continusec Pty Ltd

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

package bolt

import (
	"encoding/hex"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/verifiable"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

// Storage gives a service that persists to a BoltDB file.
type Storage struct {
	// Path is a path to a directory where we will create files, one per user Map / user Log.
	Path string

	dbLock sync.RWMutex
	dbs    map[string]*bolt.DB
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
func (bbs *Storage) getDB(key string) *bolt.DB {
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
func (bbs *Storage) getOrCreateDB(ns []byte) (*bolt.DB, error) {
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
		bbs.dbs = make(map[string]*bolt.DB)
	}

	// Check again, as may have been added since last
	rv, ok := bbs.dbs[key]
	if ok {
		return rv, nil
	}

	// Get or create on distk
	db, err := bolt.Open(filepath.Join(bbs.Path, key), 0600, &bolt.Options{Timeout: 1 * time.Second})
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
	return db.View(func(tx *bolt.Tx) error {
		return f(ctx, &boltReaderWriter{Tx: tx})
	})
}

// ExecuteUpdate executes an update query
func (bbs *Storage) ExecuteUpdate(ctx context.Context, namespace []byte, f func(ctx context.Context, db verifiable.KeyWriter) error) error {
	db, err := bbs.getOrCreateDB(namespace)
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		return f(ctx, &boltReaderWriter{Tx: tx})
	})
}

type boltReaderWriter struct {
	Tx *bolt.Tx
}

var (
	rootBucket = []byte("root")
)

func (db *boltReaderWriter) Get(ctx context.Context, key []byte, value proto.Message) error {
	b := db.Tx.Bucket(rootBucket)
	if b == nil {
		return verifiable.ErrNoSuchKey
	}
	rv := b.Get(key)
	if rv == nil { // as distinct from 0 length
		return verifiable.ErrNoSuchKey
	}
	return proto.Unmarshal(rv, value)
}

func (db *boltReaderWriter) Set(ctx context.Context, key []byte, value proto.Message) error {
	b, err := db.Tx.CreateBucketIfNotExists(rootBucket)
	if err != nil {
		return err
	}
	if value == nil {
		return b.Delete(key)
	}
	bb, err := proto.Marshal(value)
	if err != nil {
		return err
	}
	return b.Put(key, bb)
}
