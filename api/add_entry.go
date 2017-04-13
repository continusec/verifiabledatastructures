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

import "github.com/continusec/verifiabledatastructures/pb"
import "github.com/continusec/verifiabledatastructures/client"
import "encoding/json"

func (s *LocalService) addEntryToLog(db KeyWriter, log *pb.LogRef, data *pb.LeafData) (*pb.LogTreeHashResponse, error) {
	return nil, ErrNotImplemented
}

func (s *LocalService) setMapValue(db KeyWriter, vmap *pb.MapRef, treeSize int64, mut *client.JSONMapMutationEntry) ([]byte, error) {
	return nil, ErrNotImplemented
}

func mapForMutationLog(m *pb.LogRef) *pb.MapRef {
	return &pb.MapRef{
		Account: m.Account,
		Name:    m.Name,
	}
}

func treeHeadLogForMutationLog(m *pb.LogRef) *pb.LogRef {
	return &pb.LogRef{
		Account: m.Account,
		Name:    m.Name,
		LogType: pb.LogType_STRUCT_TYPE_TREEHEAD_LOG,
	}
}

func (s *LocalService) applyLogAddEntry(db KeyWriter, req *pb.LogAddEntryRequest) error {
	// Step 1 - add entry to log as request
	mutLogHead, err := s.addEntryToLog(db, req.Log, req.Data)
	if err != nil {
		return err
	}

	// Special case mutation log for maps
	if req.Log.LogType == pb.LogType_STRUCT_TYPE_MUTATION_LOG {
		// Step 2 - add entries to map if needed
		var mut client.JSONMapMutationEntry
		err = json.Unmarshal(req.Data.ExtraData, &mut)
		if err != nil {
			return err
		}
		mrh, err := s.setMapValue(db, mapForMutationLog(req.Log), mutLogHead.TreeSize, &mut)
		if err != nil {
			return err
		}

		// Step 3 - add entries to treehead log if neeed
		thld, err := jsonObjectHash(&client.JSONMapTreeHeadResponse{
			MapHash: mrh,
			LogTreeHead: &client.JSONLogTreeHeadResponse{
				Hash:     mutLogHead.RootHash,
				TreeSize: mutLogHead.TreeSize,
			},
		})
		if err != nil {
			return err
		}
		_, err = s.addEntryToLog(db, treeHeadLogForMutationLog(req.Log), thld)
		if err != nil {
			return err
		}
	}

	return nil
}
