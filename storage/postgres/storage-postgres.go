package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/continusec/verifiabledatastructures/verifiable"
	"github.com/golang/protobuf/proto"
	"github.com/jackc/pgx"
)

// Storage implements a Postgresql backed storage layer, suitable for use with the
// verifiabledatastructures library.
type Storage struct {
	Pool *pgx.ConnPool

	knownTableMutex sync.RWMutex
	knownTables     map[string]string
}

type txWriter struct {
	// Tx is the transaction asssociated with this session
	Tx *pgx.Tx

	// Table is the name of the table on which we are operating
	Table string
}

// Get must return ErrNoSuchKey if none found
func (t *txWriter) Get(ctx context.Context, key []byte, value proto.Message) error {
	var data []byte
	err := t.Tx.QueryRow(fmt.Sprintf(`SELECT value FROM "%s" WHERE key = $1`, t.Table), key).Scan(&data)
	switch err {
	case nil:
		return proto.Unmarshal(data, value)
	case pgx.ErrNoRows:
		return verifiable.ErrNoSuchKey
	default:
		return err
	}
}

// Set with value of nil means delete
func (t *txWriter) Set(ctx context.Context, key []byte, value proto.Message) error {
	if value == nil {
		_, err := t.Tx.Exec(fmt.Sprintf(`DELETE FROM "%s" WHERE key = $1`, t.Table), key)
		return err
	}

	data, err := proto.Marshal(value)
	if err != nil {
		return err
	}

	_, err = t.Tx.Exec(fmt.Sprintf(`INSERT INTO "%s" (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`, t.Table), key, data)
	return err
}

// returns appropriate tablename for namespace
func (pgs *Storage) getOrCreateNS(ctx context.Context, namespace []byte) (string, error) {
	key := string(namespace)

	// First see if we have it
	pgs.knownTableMutex.RLock()
	if pgs.knownTables != nil {
		rv, ok := pgs.knownTables[key]
		if ok {
			pgs.knownTableMutex.RUnlock()
			return rv, nil
		}
	}
	pgs.knownTableMutex.RUnlock()

	// Else, let's attempt to create in DB
	sh := sha256.Sum256(namespace) // NOTE we just use the first 16 bytes of the SHA256 hash, else we hit PG identifier limits.
	nameToUser := fmt.Sprintf("vds_%s", hex.EncodeToString(sh[:16]))

	tx, err := pgs.Pool.Begin()
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			key   bytea PRIMARY KEY,
			value bytea
		)
	`, nameToUser))
	if err != nil {
		tx.Rollback()
		return "", err
	}
	err = tx.Commit()
	if err != nil {
		return "", err
	}

	// Now store answer for next time so we don't waste DB trips
	pgs.knownTableMutex.Lock()
	defer pgs.knownTableMutex.Unlock()
	if pgs.knownTables == nil {
		pgs.knownTables = make(map[string]string)
	}
	pgs.knownTables[key] = nameToUser

	return nameToUser, nil
}

// ExecuteReadOnly executes a read only query. Note this will have the side-effect of
// creating a table for this namespace, if it doesn't already exist.
func (pgs *Storage) ExecuteReadOnly(ctx context.Context, namespace []byte, f func(ctx context.Context, db verifiable.KeyReader) error) error {
	tableName, err := pgs.getOrCreateNS(ctx, namespace)
	if err != nil {
		return err
	}

	tx, err := pgs.Pool.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	return f(ctx, &txWriter{
		Table: tableName,
		Tx:    tx,
	})
}

// ExecuteUpdate executes an update query. Only one of these can execute per-namespace
// at once, and this is enforced by a full table lock.
func (pgs *Storage) ExecuteUpdate(ctx context.Context, namespace []byte, f func(ctx context.Context, db verifiable.KeyWriter) error) error {
	tableName, err := pgs.getOrCreateNS(ctx, namespace)
	if err != nil {
		return err
	}

	tx, err := pgs.Pool.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Only one update per table to run at once...
	_, err = tx.Exec(fmt.Sprintf(`LOCK TABLE "%s" IN EXCLUSIVE MODE`, tableName))
	if err != nil {
		return err
	}

	err = f(ctx, &txWriter{
		Table: tableName,
		Tx:    tx,
	})
	if err != nil {
		return err
	}

	return tx.Commit()
}
