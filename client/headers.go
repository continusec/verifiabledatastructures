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

package client

import (
	"errors"

	"github.com/continusec/verifiabledatastructures/pb"

	"golang.org/x/net/context"
)

// Head can be used where tree sizes are accepted to represent the latest tree size.
// Most typically this is used with TreeHead() calls where the latest tree size is not
// yet known.
const Head = int64(0)

var (
	// ErrNotAuthorized is returned when the request is understood, but there are no API access
	// rules specified that allow such access. Check the API Key and account number passed are correct,
	// and that you are trying to access the log/map with the appropriate name.
	ErrNotAuthorized = errors.New("Unauthorized request. Check API key, account and log/map name")

	// ErrInternalError is an unspecified error. Contact info@continusec.com if these persist.
	ErrInternalError = errors.New("Unspecified error.")

	// ErrInvalidRange is returned when an invalid index is specified in the request, for example
	// if a tree size is specified that is greater than the current size of the tree / map.
	ErrInvalidRange = errors.New("Invalid range requested.")

	// ErrNotFound is returned when the request is understood and authorized, however the underlying
	// map/log cannot be found. Check the name of the map/log and verify that you have already created it.
	// This is also returned if an inclusion proof is requested for a non-existent element.
	ErrNotFound = errors.New("Can't find log/map/entry. Check the log/map/entry is created.")

	// Verification of proof failed.
	ErrVerificationFailed = errors.New("ErrVerificationFailed")

	// Object may already exist
	ErrObjectConflict = errors.New("ErrObjectConflict")

	// A nil tree head was unexpectedly passed as input
	ErrNilTreeHead = errors.New("ErrNilTreeHead")

	// ErrNotAllEntriesReturned can occur if Json is requested, but the data on the server was
	// not stored in that manner. If in doubt, RawDataEntryFactory will always succeed regardless of input format.
	ErrNotAllEntriesReturned = errors.New("ErrNotAllEntriesReturned")

	// ErrInvalidJSON occurs when there is invalid JSON
	ErrInvalidJSON = errors.New("ErrInvalidJSON")
)

// LogAuditFunction is a function that is called for all matching log entries.
// Return non-nil to stop the audit.
type LogAuditFunction func(ctx context.Context, idx int64, entry *pb.LeafData) error

type MapUpdatePromise interface {
	Wait() (*pb.MapTreeHashResponse, error)
	LeafHash() []byte
}

type LogUpdatePromise interface {
	Wait() (*pb.LogTreeHashResponse, error)
	LeafHash() []byte
}
