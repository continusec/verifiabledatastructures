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

// AnythingGoesOracle allows all operations on all fields, all the time
type AnythingGoesOracle struct{}

// VerifyAllowed always returns nil, and allows access to all fields
func (o *AnythingGoesOracle) VerifyAllowed(account, apiKey, objectName string, permisson pb.Permission) (*AccessModifier, error) {
	return &AccessModifier{
		FieldFilter: AllFields,
	}, nil
}

// StaticOracle applies a policy based on the configuration file specified.
type StaticOracle struct {
	Policy []*pb.Account
}

// VerifyAllowed returns value as specifed in the policy
func (o *StaticOracle) VerifyAllowed(account, apiKey, objectName string, permisson pb.Permission) (*AccessModifier, error) {
	return &AccessModifier{
		FieldFilter: AllFields,
	}, nil
}
