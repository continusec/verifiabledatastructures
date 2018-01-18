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

package postgresql

import (
	"database/sql"
	"fmt"
	"net/url"
	"sync"

	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/verifiable"

	_ "github.com/lib/pq"
)

// Postgresql stores values in a pg database. It doesn't do it terribly well,
// this can be nice for demos
type Postgresql struct {
	Hostname string
	Database string
	Port     int
	Username string
	Password string

	dbMutex sync.Mutex
	db      *sql.DB
}

func (pg *Postgresql) connString() string {
	return (&url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(pg.Username, pg.Password),
		Host:   fmt.Sprintf("%s:%d", pg.Hostname, pg.Port),
		Path:   fmt.Sprintf("/%s", url.PathEscape(pg.Database)),
	}).String()
}

func (pg *Postgresql) getDB(ns []byte) (*sql.DB, error) {
	pg.dbMutex.Lock()
	defer pg.dbMutex.Unlock()

	if pg.db == nil {
		var err error
		pg.db, err = sql.Open("postgres", pg.connString())
		if err != nil {
			return nil, err
		}
	}

	return pg.db, nil
}

func (pg *Postgresql) 

func (pg *Postgresql) Close() error {
	pg.dbMutex.Lock()
	defer pg.dbMutex.Unlock()

	if pg.db == nil {
		return nil
	}

	rv := pg.db.Close()
	pg.db = nil
	return rv
}

// ExecuteReadOnly executes a read only query
func (pg *Postgresql) ExecuteReadOnly(ctx context.Context, namespace []byte, f func(ctx context.Context, db verifiable.KeyReader) error) error {
	return verifiable.ErrNotImplemented
}

// ExecuteUpdate executes an update query
func (pg *Postgresql) ExecuteUpdate(ctx context.Context, namespace []byte, f func(ctx context.Context, db verifiable.KeyWriter) error) error {
	conn, err := pg.connect()
	if err != nil {
		return err
	}

	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: false})
	if err != nil {
		return err
	}

	return verifiable.ErrNotImplemented
}
