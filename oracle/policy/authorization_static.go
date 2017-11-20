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
	"path"
	"strings"

	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/verifiable"
	"golang.org/x/net/context"
)

// Static applies a policy based on the configuration data specified.
type Static struct {
	Policy []*pb.ResourceAccount
}

// VerifyAllowed returns value as specifed in the policy
func (o *Static) VerifyAllowed(ctx context.Context, account, apiKey, objectName string, permission pb.Permission) (*verifiable.AccessModifier, error) {
	// TODO, optimize the following, which is currently a set of nested dumb loops, unsuitable for anything non-trivial
	for _, acc := range o.Policy { // for each account in the policy
		if acc.Id == account { // if it is the one we are accessing
			for _, pol := range acc.Policy { // then for each line in that account policy
				for _, perm := range pol.Permissions { // look at the permissions in that line
					if perm == pb.Permission_PERM_ALL_PERMISSIONS || perm == permission { // if that includes our requested permission, or is a wildcard permission
						if pol.ApiKey == "*" || (len(pol.ApiKey) != 0 && pol.ApiKey == apiKey) { // then if we have the API key matching this line, or if the line matches all API keys
							matched, err := path.Match(pol.NameMatch, objectName) // then see if we glob match the name of the object being accessed
							if matched && err == nil {                            // and then, if so,
								return &verifiable.AccessModifier{ // return the allowed field list!
									FieldFilter: strings.Join(pol.AllowedFields, ","),
								}, nil
							}
						}
					}
				}
			}
		}
	}
	// Default deny
	return nil, verifiable.ErrNotAuthorized
}
