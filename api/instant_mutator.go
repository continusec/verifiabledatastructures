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

type InstantMutator struct {
	Writer  StorageWriter
	Service MutatorApplier
}

func (m *InstantMutator) QueueMutation(mut *pb.Mutation) (MutatorPromise, error) {
	return &instancePromise{Err: m.Writer.ExecuteUpdate(mut.Namespace, func(kw KeyWriter) error {
		return m.Service.ApplyMutation(kw, mut)
	})}, nil
}

type instancePromise struct {
	Err error
}

func (i *instancePromise) WaitUntilDone() error {
	return i.Err
}
