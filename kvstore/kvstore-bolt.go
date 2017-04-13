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

package kvstore

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"sync"
	"time"

	"os"

	"github.com/boltdb/bolt"
	"github.com/continusec/verifiabledatastructures/api"
)

// BoltBackedService gives a service that persists to a BoltDB file.
type BoltBackedService struct {
	Path string

	dbLock sync.Mutex
	dbs    map[string]*bolt.DB
}

func (bbs *BoltBackedService) ResetNamespace(ns []byte, recreate bool) error {
	err := bbs.dropDB(ns)
	if err != nil {
		return err
	}
	if recreate {
		_, err = bbs.getDB(ns, true)
		return err
	}
	return nil
}

func (bbs *BoltBackedService) dropDB(ns []byte) error {
	key := hex.EncodeToString(ns)

	bbs.dbLock.Lock()
	defer bbs.dbLock.Unlock()

	if bbs.dbs != nil {
		delete(bbs.dbs, key)
	}

	fpath := filepath.Join(bbs.Path, key)
	err := os.Remove(fpath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (bbs *BoltBackedService) getDB(ns []byte, create bool) (*bolt.DB, error) {
	key := hex.EncodeToString(ns)

	bbs.dbLock.Lock()
	defer bbs.dbLock.Unlock()

	if bbs.dbs == nil {
		bbs.dbs = make(map[string]*bolt.DB)
	}

	rv, ok := bbs.dbs[key]
	if ok {
		return rv, nil
	}

	fpath := filepath.Join(bbs.Path, key)

	if !create {
		_, err := os.Stat(fpath)
		if err != nil {
			return nil, err
		}
	}

	db, err := bolt.Open(fpath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	bbs.dbs[key] = db

	return db, nil
}

func (bbs *BoltBackedService) ExecuteReadOnly(namespace []byte, f func(db api.KeyReader) error) error {
	db, err := bbs.getDB(namespace, false)
	if err != nil {
		return err
	}
	return db.View(func(tx *bolt.Tx) error {
		return f(&boltReaderWriterGetter{Tx: tx})
	})
}
func (bbs *BoltBackedService) ExecuteUpdate(namespace []byte, f func(db api.KeyWriter) error) error {
	db, err := bbs.getDB(namespace, true) // TODO - should this really create a database?
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		return f(&boltReaderWriterGetter{Tx: tx})
	})
}

type boltReaderWriterGetter struct {
	Tx *bolt.Tx
}

func (db *boltReaderWriterGetter) Get(bucket, key []byte) ([]byte, error) {
	b := db.Tx.Bucket(bucket)
	if b == nil {
		return nil, api.ErrNoSuchKey
	}
	rv := b.Get(key)
	if rv == nil { // as distinct from 0 length
		return nil, api.ErrNoSuchKey
	}
	return rv, nil
}
func (db *boltReaderWriterGetter) Range(bucket, first, last []byte) ([][2][]byte, error) {
	rv := make([][2][]byte, 0)
	b := db.Tx.Bucket(bucket)
	if b == nil {
		return rv, nil
	}
	c := b.Cursor()
	k, v := c.Seek(first)
	for k != nil && ((first == nil && last == nil) || bytes.Compare(k, last) == -1) {
		rv = append(rv, [2][]byte{k, v})
		k, v = c.Next()
	}
	return rv, nil
}
func (db *boltReaderWriterGetter) Set(bucket, key, value []byte) error {
	b, err := db.Tx.CreateBucketIfNotExists(bucket)
	if err != nil {
		return err
	}
	if value == nil {
		return b.Delete(key)
	}
	return b.Put(key, value)
}
