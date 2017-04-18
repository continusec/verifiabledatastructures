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
	"github.com/golang/protobuf/proto"
)

var (
	// ErrInvalidJSON needs to be documented
	ErrInvalidJSON = errors.New("ErrInvalidJSON")

	// ErrNotFound needs to be documented
	ErrNotFound = errors.New("ErrNotFound")

	// ErrAlreadyNotActive needs to be documented
	ErrAlreadyNotActive = errors.New("ErrAlreadyNotActive")

	// ErrNotAuthorized needs to be documented
	ErrNotAuthorized = errors.New("Unauthorized request")

	// ErrInvalidTreeRange needs to be documented
	ErrInvalidTreeRange = errors.New("Invalid index")

	// ErrSubTreeHashShouldBeForPow2Only needs to be documented
	ErrSubTreeHashShouldBeForPow2Only = errors.New("Subtree hash is used for powers of 2 only")

	// ErrNotReadyYet needs to be documented
	ErrNotReadyYet = errors.New("Tree hashes still calculating")

	// ErrLogAlreadyExists needs to be documented
	ErrLogAlreadyExists = errors.New("ErrLogAlreadyExists")

	// ErrLogUnsafeForAccess needs to be documented
	ErrLogUnsafeForAccess = errors.New("ErrLogUnsafeForAccess")

	// ErrNotImplemented needs to be documented
	ErrNotImplemented = errors.New("ErrNotImplemented")

	// ErrInvalidRequest needs to be documented
	ErrInvalidRequest = errors.New("ErrInvalidRequest")

	// ErrNoSuchKey needs to be documented
	ErrNoSuchKey = errors.New("ErrNoSuchKey")
)

// MutatorService receives requested mutations
type MutatorService interface {
	// QueueMutation requests an asynchronous mutation in a namespace.
	QueueMutation(namespace []byte, mut *pb.Mutation) (MutatorPromise, error)
}

// MutatorPromise is a promise that a mutation will complete.
type MutatorPromise interface {
	// Wait waits for the mutation to apply
	Wait() error
}

const (
	// AllFields is a field filter that represents all fields
	AllFields = "*"
)

// AccessModifier includes any extra context about how the user can access the data
type AccessModifier struct {
	// FieldFilter, if set to a value other than AllFields, will result in ExtraData fields being appropriately filtered.
	FieldFilter string
}

// AuthorizationOracle determines if a user requested operation is allowed or not
type AuthorizationOracle interface {
	// VerifyAllowed returns nil if operation is allowed. Other values means no
	VerifyAllowed(account, apiKey, objectName string, permisson pb.Permission) (*AccessModifier, error)
}

// StorageReader can execute read-only transactions on a given namespace
type StorageReader interface {
	// ExecuteReadOnly safely reads that from a namespace
	ExecuteReadOnly(namespace []byte, f func(db KeyReader) error) error
}

// StorageWriter can execute write transcations on a given namespace
type StorageWriter interface {
	// ExecuteUpdate performs an update on a given namespace. For now it is required
	// that only one update takes place at a time, ie all updates are sequential.
	ExecuteUpdate(namespace []byte, f func(db KeyWriter) error) error
}

// KeyReader allows read access to a namespace
type KeyReader interface {
	// Get reads the value for key in a bucket into a proto.
	// It must return nil, ErrNoSuchKey if none found
	Get(bucket, key []byte, value proto.Message) error
}

// KeyWriter allows write access to a namespace
type KeyWriter interface {
	KeyReader

	// Set sets the thing. Value of nil means delete.
	Set(bucket, key []byte, value proto.Message) error
}
