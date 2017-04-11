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
	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/pb"
)

type LocalService struct {
	Mutator      MutatorService
	AccessPolicy AuthorizationOracle
	Reader       StorageReader
}

func (s *LocalService) LogCreate(context.Context, *pb.LogCreateRequest) (*pb.LogCreateResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) LogDelete(context.Context, *pb.LogDeleteRequest) (*pb.LogDeleteResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) LogList(context.Context, *pb.LogListRequest) (*pb.LogListResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) LogAddEntry(context.Context, *pb.LogAddEntryRequest) (*pb.LogAddEntryResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) LogFetchEntries(context.Context, *pb.LogFetchEntriesRequest) (*pb.LogFetchEntriesResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) LogTreeHash(context.Context, *pb.LogTreeHashRequest) (*pb.LogTreeHashResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) LogInclusionProof(context.Context, *pb.LogInclusionProofRequest) (*pb.LogInclusionProofResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) LogConsistencyProof(context.Context, *pb.LogConsistencyProofRequest) (*pb.LogConsistencyProofResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) MapCreate(context.Context, *pb.MapCreateRequest) (*pb.MapCreateResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) MapDelete(context.Context, *pb.MapDeleteRequest) (*pb.MapDeleteResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) MapList(context.Context, *pb.MapListRequest) (*pb.MapListResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) MapSetValue(context.Context, *pb.MapSetValueRequest) (*pb.MapSetValueResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) MapGetValue(context.Context, *pb.MapGetValueRequest) (*pb.MapGetValueResponse, error) {
	return nil, ErrNotImplemented
}
func (s *LocalService) MapTreeHash(context.Context, *pb.MapTreeHashRequest) (*pb.MapTreeHashResponse, error) {
	return nil, ErrNotImplemented
}
