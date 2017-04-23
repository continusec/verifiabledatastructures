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
	"golang.org/x/net/context"

	"github.com/golang/protobuf/proto"
)

// StorageReader can execute read-only transactions on a given namespace
type StorageReader interface {
	// ExecuteReadOnly safely reads that from a namespace
	ExecuteReadOnly(ctx context.Context, namespace []byte, f func(ctx context.Context, db KeyReader) error) error
}

// StorageWriter can execute write transcations on a given namespace
type StorageWriter interface {
	StorageReader

	// ExecuteUpdate performs an update on a given namespace. For now it is required
	// that only one update takes place at a time, ie all updates are sequential.
	ExecuteUpdate(ctx context.Context, namespace []byte, f func(ctx context.Context, db KeyWriter) error) error
}

// KeyReader allows read access to a namespace
type KeyReader interface {
	// Get reads the value for key in a bucket into a proto.
	// It must return nil, ErrNoSuchKey if none found
	Get(ctx context.Context, bucket, key []byte, value proto.Message) error
}

// KeyWriter allows write access to a namespace
type KeyWriter interface {
	KeyReader

	// Set sets the thing. Value of nil means delete.
	Set(ctx context.Context, bucket, key []byte, value proto.Message) error
}
