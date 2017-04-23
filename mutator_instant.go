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

	"github.com/continusec/verifiabledatastructures/pb"
)

// InstantMutator will synchronously apply the mutation. This is suitable
// for test and low-usage environments.
type InstantMutator struct {
	// Writer is the database to apply the mutations
	Writer StorageWriter
}

// QueueMutation applies the mutation, normally asynchronously, but synchronously for the InstantMutator
func (m *InstantMutator) QueueMutation(ctx context.Context, ns []byte, mut *pb.Mutation) error {
	return m.Writer.ExecuteUpdate(ctx, ns, func(kw KeyWriter) error {
		startSize, err := readObjectSize(ctx, kw)
		if err != nil {
			return err
		}
		nextSize, err := ApplyMutation(ctx, kw, startSize, mut)
		if err != nil {
			return err
		}
		if nextSize != startSize {
			err = writeObjectSize(ctx, kw, nextSize)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
