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

//go:generate protoc --go_out=plugins=grpc:../../.. -Iproto proto/api.proto proto/configuration.proto proto/storage.proto
//go:generate go-bindata -pkg assets -o assets/assets.go assets/static/

package verifiabledatastructures

import (
	"github.com/continusec/verifiabledatastructures/pb"
	"golang.org/x/net/context"
)

// Head can be used where tree sizes are accepted to represent the latest tree size.
// Most typically this is used with TreeHead() calls where the latest tree size is not
// yet known.
const Head = int64(0)

// LogAuditFunction is a function that is called for all matching log entries.
// Return non-nil to stop the audit.
type LogAuditFunction func(ctx context.Context, idx int64, entry *pb.LeafData) error

// MapUpdatePromise is returned by operations that change a map.
type MapUpdatePromise interface {
	// Wait will wait for the mutation to apply to the map, generally this is done by polling the map.
	Wait(ctx context.Context) (*pb.MapTreeHashResponse, error)

	// LeafHash returns the hash of the queued mutation log entry. This can be used to poll the mutation log.
	LeafHash() []byte
}

// LogUpdatePromise is returned by operations that change a log.
type LogUpdatePromise interface {
	// Wait will wait for the add to apply to the log, generally this is done by polling the log.
	Wait(ctx context.Context) (*pb.LogTreeHashResponse, error)

	// LeafHash returns the hash of the queued log entry. This can be used to poll the log.
	LeafHash() []byte
}

// LeafDataAuditFunction validates that a pb.LeafData object is correctly constructed.
// Generally this means to verify that the LeafInput is correctly derived from the other fields.
type LeafDataAuditFunction func(context.Context, *pb.LeafData) error

// MapAuditFunction is a function called by a map auditor after a MapMutation has been to
// an audited map, and verified to have been processsed correctly by the map. This function
// gives an opportunity for a map auditor to indicate success/failure of the audit based on
// other characteristics, such as correctness of the values of the entires.
// Note that this is only called if the mutation resulted in a change to the map root hash,
// so for example it is not called for a mutation that does not modify the value for a key,
// such as setting the same value again (that is already set), or updates based on a previous
// value where the previous value is not current.
// idx the index of the mutation - while this will always increase, there may be gaps per the
// reasons outlined above.
// key is the key that is being changed
// value (produced by VerifiableEntryFactory specified when creating the auditor) is the
//  value being set/deleted/modified.
type MapAuditFunction func(ctx context.Context, idx int64, key []byte, value *pb.LeafData) error
