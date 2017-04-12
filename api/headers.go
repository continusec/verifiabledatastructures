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

	"github.com/continusec/verifiabledatastructures/pb"
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
	ErrNotImplemented                 = errors.New("ErrNotImplemented")
	ErrInvalidRequest                 = errors.New("ErrInvalidRequest")
	ErrNoSuchKey                      = errors.New("ErrNoSuchKey")
)

type MutatorService interface {
	QueueMutation(namespace []byte, mut *pb.Mutation) (MutatorPromise, error)
}

type MutatorApplier interface {
	ApplyMutation(db KeyWriter, mut *pb.Mutation) error
}

type MutatorPromise interface {
	WaitUntilDone() error
}

type AuthorizationOracle interface {
	// VerifyAllowed returns nil if operation is allowed. Other values means no
	VerifyAllowed(account, apiKey, objectName string, permisson pb.Permission) error
}

type StorageReader interface {
	ExecuteReadOnly(namespace []byte, f func(db KeyReader) error) error
}

type StorageWriter interface {
	ExecuteUpdate(namespace []byte, f func(db KeyWriter) error) error
}

type KeyGetter interface {
	// Get returns ErrNoSuchKey if none found
	Get(bucket, key []byte) ([]byte, error)
}

type KeyReader interface {
	KeyGetter

	// Range returns a list of matching <key, value> tuples where the first <= key < last
	Range(bucket, first, last []byte) ([][2][]byte, error)
}

type KeyWriter interface {
	KeyGetter

	// Set sets the thing. Value of nil means delete
	Set(bucket, key, value []byte) error

	// ResetNamespace deletes the namespace if it already exists.
	// It is not an error if it doesn't already exist.
	// If recreate is set, then create a new namespace
	ResetNamespace(ns []byte, recreate bool) error
}
