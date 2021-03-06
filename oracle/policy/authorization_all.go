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

package policy

import (
	"golang.org/x/net/context"

	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/verifiable"
)

var (
	// Open allows all operations on all fields, all the time
	Open = verifiable.AuthorizationOracle(&anythingGoes{})
)

type anythingGoes struct{}

// VerifyAllowed always returns nil, and allows access to all fields
func (o *anythingGoes) VerifyAllowed(ctx context.Context, account, apiKey, objectName string, permisson pb.Permission) (*verifiable.AccessModifier, error) {
	return &verifiable.AccessModifier{
		FieldFilter: verifiable.AllFields,
	}, nil
}
