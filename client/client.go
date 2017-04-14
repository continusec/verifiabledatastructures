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

// Package continusec provides golang client libraries for interacting with the
// verifiable datastructures provided by Continusec.
//
// Sample usage is as follows:
//
//     import (
//         "github.com/continusec/go-client/continusec"
//     )
//
//     // Construct a client
//     client := continusec.DefaultClient.WithApiKey("<your API key>")
//
//     // If on Google App Engine:
//     client = client.WithHttpClient(urlfetch.Client(ctx))
//
//     // Get a pointer to your account
//     account := &continusec.Account{Account: "<your account number>", Client: client}
//
//     // Get a pointer to a log
//     log := account.VerifiableLog("testlog")
//
//     // Create a log (only do this once)
//     err := log.Create()
//     if err != nil { ... }
//
//     // Add entry to log
//     _, err = log.Add(&continusec.RawDataEntry{RawBytes: []byte("foo")})
//     if err != nil { ... }
//
//     // Get latest verified tree head
//     prev := ... load from storage ...
//     head, err := log.VerifiedLatestTreeHead(prev)
//     if err != nil { ... }
//     if head.TreeSize > prev.TreeSize {
//         ... save head to storage ...
//     }
//
//     // Prove inclusion of item in tree head
//     err = log.VerifyInclusion(head, &continusec.RawDataEntry{RawBytes: []byte("foo")})
//     if err != nil { ... }
//
//     // Get a pointer to a map
//     vmap := account.VerifiableMap("testmap")
//
//     // Create a map (only do this once)
//     err := vmap.Create()
//     if err != nil { ... }
//
//     // Set value in the map
//     _, err = _, err = vmap.Set([]byte("foo"), &continusec.RawDataEntry{RawBytes: []byte("bar")})
//     if err != nil { ... }
//
//     // Get latest verified map state
//     prev := ... load from storage ...
//     head, err := vmap.VerifiedLatestMapState(prev)
//     if err != nil { ... }
//     if head.TreeSize() > prev.TreeSize() {
//         ... save head to storage ...
//     }
//
//     // Get value and verify its inclusion in head
//     entry, err := vmap.VerifiedGet([]byte("foo"), head, continusec.RawDataEntryFactory)
//     if err != nil { ... }
//
package client

import "net/http"

var (
	// DefaultClient uses the default base URL and default HttpClient.
	DefaultClient = &HTTPRESTClient{
		BaseUrl:    "https://api.continusec.com/v1",
		HttpClient: http.DefaultClient,
	}
)
