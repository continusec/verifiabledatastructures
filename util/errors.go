package util

import "errors"

var (
	// ErrAlreadyNotActive needs to be documented
	ErrAlreadyNotActive = errors.New("ErrAlreadyNotActive")

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

	// ErrNotAuthorized is returned when the request is understood, but there are no API access
	// rules specified that allow such access. Check the API Key and account number passed are correct,
	// and that you are trying to access the log/map with the appropriate name.
	ErrNotAuthorized = errors.New("Unauthorized request. Check API key, account and log/map name")

	// ErrInternalError is an unspecified error. Contact info@continusec.com if these persist.
	ErrInternalError = errors.New("Unspecified error")

	// ErrInvalidRange is returned when an invalid index is specified in the request, for example
	// if a tree size is specified that is greater than the current size of the tree / map.
	ErrInvalidRange = errors.New("Invalid range requested")

	// ErrNotFound is returned when the request is understood and authorized, however the underlying
	// map/log cannot be found. Check the name of the map/log and verify that you have already created it.
	// This is also returned if an inclusion proof is requested for a non-existent element.
	ErrNotFound = errors.New("Can't find log/map/entry. Check the log/map/entry is created")

	// ErrVerificationFailed means that verification of proof failed.
	ErrVerificationFailed = errors.New("Failed to verify")

	// ErrObjectConflict is not used
	ErrObjectConflict = errors.New("ErrObjectConflict")

	// ErrNilTreeHead means a nil tree head was unexpectedly passed as input
	ErrNilTreeHead = errors.New("ErrNilTreeHead")

	// ErrNotAllEntriesReturned can occur if Json is requested, but the data on the server was
	// not stored in that manner. If in doubt, RawDataEntryFactory will always succeed regardless of input format.
	ErrNotAllEntriesReturned = errors.New("ErrNotAllEntriesReturned")

	// ErrInvalidJSON occurs when there is invalid JSON
	ErrInvalidJSON = errors.New("ErrInvalidJSON")
)