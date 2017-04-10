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

package kvstore

import "github.com/continusec/go-client/continusec"

type bbAccount struct {
	service *BoltBackedService
	apiKey  string
	account string
}

// VerifiableMap returns an object representing a Verifiable Map. This function simply
// returns a pointer to an object that can be used to interact with the Map, and won't
// by itself cause any API calls to be generated.
func (acc *bbAccount) VerifiableMap(name string) continusec.VerifiableMap {
	return &bbMap{
		account: acc,
		name:    name,
	}
}

// VerifiableLog returns an object representing a Verifiable Log. This function simply
// returns a pointer to an object that can be used to interact with the Log, and won't
// by itself cause any API calls to be generated.
func (acc *bbAccount) VerifiableLog(name string) continusec.VerifiableLog {
	return &bbLog{
		account: acc,
		name:    name,
		logType: logTypeUser,
	}
}

// ListLogs returns a list of logs held by the account
func (acc *bbAccount) ListLogs() ([]continusec.VerifiableLog, error) {
	return nil, ErrNotImplemented
}

// ListMaps returns a list of maps held by the account
func (acc *bbAccount) ListMaps() ([]continusec.VerifiableMap, error) {
	return nil, ErrNotImplemented
}
