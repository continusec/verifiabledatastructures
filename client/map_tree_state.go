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

import "github.com/continusec/verifiabledatastructures/pb"

// MapTreeState represents the current state of a map, intended for persistence by callers.
// It combines the MapTreeHead which is the current state, with the LogTreeHead for the underlying
// tree head log which has been verified to include this MapTreeHead
type MapTreeState struct {
	// MapTreeHead is the root hash / mutation tree head for the map at this time.
	MapTreeHead *pb.MapTreeHashResponse

	// TreeHeadLogTreeHead is a TreeHead for the Tree Head log, which contains this Map Tree Head.
	// The tree size in this log tree head may be different to that in the mutation log tree head.
	// The TreeSize of this MapTreeState is dictated by the tree size of the Mutation Log which the map root hash represents.
	TreeHeadLogTreeHead *pb.LogTreeHashResponse
}

// TreeSize is a utility method for returning the tree size of the underlying map.
func (self *MapTreeState) TreeSize() int64 {
	return self.MapTreeHead.MutationLog.TreeSize
}
