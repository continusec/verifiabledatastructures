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
	"errors"
	"time"

	"github.com/boltdb/bolt"
	"github.com/continusec/go-client/continusec"
	"github.com/continusec/vds-server/pb"
)

var (
	ErrNotImplemented = errors.New("ErrNotImplemented")
)

// BoltBackedService gives a service that persists to a BoltDB file.
type BoltBackedService struct {
	Path     string
	Accounts []*pb.Account

	db *bolt.DB
}

// Init must be called before use
func (bbs *BoltBackedService) Init() error {
	var err error
	bbs.db, err = bolt.Open(bbs.Path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	return err
}

// CreateClient returns a client to the BoltBackedService.
func (bbs *BoltBackedService) Account(account string, apiKey string) continusec.Account {
	return &bbAccount{
		service: bbs,
		account: account,
		apiKey:  apiKey,
	}
}
