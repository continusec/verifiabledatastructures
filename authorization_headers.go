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

const (
	// AllFields is a field filter that represents all fields
	AllFields = "*"
)

// AccessModifier includes any extra context about how the user can access the data
type AccessModifier struct {
	// FieldFilter, if set to a value other than AllFields, will result in ExtraData fields being appropriately filtered.
	FieldFilter string
}

// AuthorizationOracle determines if a user requested operation is allowed or not
type AuthorizationOracle interface {
	// VerifyAllowed returns nil if operation is allowed. Other values means no
	VerifyAllowed(ctx context.Context, account, apiKey, objectName string, permisson pb.Permission) (*AccessModifier, error)
}
