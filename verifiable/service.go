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

package verifiable

import (
	"context"
	"log"

	"github.com/continusec/verifiabledatastructures/pb"
)

// Service is the main object used to create an instance of the server or embedded
// Verifiable Data Structures API. It may be wrapped by client directly, or used to
// start a gRPC and/or HTTP REST server
type Service struct {
	pb.UnimplementedVerifiableDataStructuresServiceServer

	// Mutator, if set is where mutations for the logs and maps are sent. If nil, we are readonly
	Mutator MutatorService

	// AccessPolicy determines if a user initiated operation is allowed or not
	AccessPolicy AuthorizationOracle

	// Reader points to the underlying data that we can read from
	Reader StorageReader
}

type localServiceImpl Service

// Create returns a low-level API object to interact with the specified service
func (l *Service) Create() (pb.VerifiableDataStructuresServiceServer, error) {
	return (*localServiceImpl)(l), nil
}

// MustCreate is a convenience method that exits with a fatal error if the operation fails
func (l *Service) MustCreate() pb.VerifiableDataStructuresServiceServer {
	rv, err := l.Create()
	if err != nil {
		log.Fatal(err)
	}
	return rv
}

// ApplyMutation should be called by a MutatorService to apply the given mutation to a log/map
func ApplyMutation(ctx context.Context, db KeyWriter, sizeBefore int64, mut *pb.Mutation) (int64, error) {
	switch {
	case mut.LogAddEntry != nil:
		return applyLogAddEntry(ctx, db, sizeBefore, mut.LogAddEntry)
	default:
		return 0, ErrNotImplemented
	}
}
