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
	"github.com/continusec/verifiabledatastructures/client"
)

type serverAccount struct {
	Service *LocalService
	APIKey  string
	Account string
}

// VerifiableMap returns an object representing a Verifiable Map. This function simply
// returns a pointer to an object that can be used to interact with the Map, and won't
// by itself cause any API calls to be generated.
func (acc *serverAccount) VerifiableMap(name string) client.VerifiableMap {
	return &serverMap{
		account: acc,
		name:    name,
	}
}

// VerifiableLog returns an object representing a Verifiable Log. This function simply
// returns a pointer to an object that can be used to interact with the Log, and won't
// by itself cause any API calls to be generated.
func (acc *serverAccount) VerifiableLog(name string) client.VerifiableLog {
	return &serverLog{
		account: acc,
		name:    name,
		logType: logTypeUser,
	}
}

// ListLogs returns a list of logs held by the account
func (acc *serverAccount) ListLogs() ([]client.VerifiableLog, error) {
	return nil, ErrNotImplemented
}

// ListMaps returns a list of maps held by the account
func (acc *serverAccount) ListMaps() ([]client.VerifiableMap, error) {
	return nil, ErrNotImplemented
}
