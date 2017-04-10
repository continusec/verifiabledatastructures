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
	QueueMutation(mut *pb.Mutation) (MutatorPromise, error)
}

type MutatorPromise interface {
	WaitUntilDone() error
}

type AuthorizationOracle interface {
	// VerifyAllowed returns nil if operation is allowed. Other values means no
	VerifyAllowed(account, apiKey, objectName string, permisson pb.Permission) error
}

type StorageReader interface {
	ExecuteReadOnly(f func(db KeyReader) error) error
}

type KeyReader interface {
	// Get returns ErrNoSuchKey if none found
	Get(bucket, key []byte) ([]byte, error)
}
