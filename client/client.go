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

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Client is the object that will be used to make requests to the Continusec API.
// Normally DefaultClient is used, with modifications as shown below.
type Client struct {
	// The base URL to use for constructing requests.
	BaseUrl string

	// The client to use for sending requests.
	HttpClient *http.Client

	// If set, authorization header to add to each request
	Authorization string
}

// WithBaseUrl returns a new client with a different base Url.
func (client *Client) WithBaseUrl(baseUrl string) *Client {
	return &Client{
		BaseUrl:       baseUrl,
		HttpClient:    client.HttpClient,
		Authorization: client.Authorization,
	}
}

// WithHttpClient returns a new client with a different http client.
// This is useful for applications hosted on Google App Engine that may wish to call:
// client.WithHttpClient(urlfetch.Client(ctx))
func (client *Client) WithHttpClient(httpClient *http.Client) *Client {
	return &Client{
		BaseUrl:       client.BaseUrl,
		HttpClient:    httpClient,
		Authorization: client.Authorization,
	}
}

// WithApiKey returns a new client with a specific API Key
func (client *Client) withApiKey(apiKey string) *Client {
	return client.withAuthorizationHeader("Key " + apiKey)
}

// WithAuthorizationHeader returns a new client with a different authorization header.
func (client *Client) withAuthorizationHeader(h string) *Client {
	return &Client{
		BaseUrl:       client.BaseUrl,
		HttpClient:    client.HttpClient,
		Authorization: h,
	}
}

// WithChildPath returns a new client with a base URL (path is appended to existing base URL).
func (client *Client) WithChildPath(path string) *Client {
	return client.WithBaseUrl(client.BaseUrl + path)
}

// Intended for internal use, MakeRequest makes an HTTP request and converts the error
// code to those appropriate for the rest of the library.
func (self *Client) MakeRequest(method, path string, data []byte, headers [][2]string) ([]byte, http.Header, error) {
	req, err := http.NewRequest(method, self.BaseUrl+path, bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	if self.Authorization != "" {
		req.Header.Set("Authorization", self.Authorization)
	}
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	resp, err := self.HttpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	switch resp.StatusCode {
	case 200:
		return contents, resp.Header, nil
	case 403:
		return nil, nil, ErrNotAuthorized
	case 400:
		return nil, nil, ErrInvalidRange
	case 404:
		return nil, nil, ErrNotFound
	case 409:
		return nil, nil, ErrObjectConflict
	default:
		return nil, nil, ErrInternalError
	}
}

func (c *Client) Account(id, apiKey string) Account {
	return &accountImpl{
		Account: id,
		Client:  c.withApiKey(apiKey),
	}
}

var (
	// DefaultClient uses the default base URL and default HttpClient.
	DefaultClient = &Client{
		BaseUrl:    "https://api.continusec.com/v1",
		HttpClient: http.DefaultClient,
	}
)

// Account is used to access your Continusec account. Leave APIKey empty to specify
// that no authorization should be sent.
type accountImpl struct {
	// Account although accepted as a string, is usually the integer shown on your account
	// settings page.
	Account string

	// Client is the client to use for sending requests.
	// Normally this is DefaultClient.WithApiKey("xxx") where
	// xxx is an API Key created on your Access Rules page.
	Client *Client
}

// VerifiableMap returns an object representing a Verifiable Map. This function simply
// returns a pointer to an object that can be used to interact with the Map, and won't
// by itself cause any API calls to be generated.
func (self *accountImpl) VerifiableMap(name string) VerifiableMap {
	return &verifiableMapImpl{
		Client:  self.Client.WithChildPath(fmt.Sprintf("/account/%s/map/%s", self.Account, name)),
		MapName: name,
	}
}

// VerifiableLog returns an object representing a Verifiable Log. This function simply
// returns a pointer to an object that can be used to interact with the Log, and won't
// by itself cause any API calls to be generated.
func (self *accountImpl) VerifiableLog(name string) VerifiableLog {
	return &verifiableLogImpl{
		Client:  self.Client.WithChildPath(fmt.Sprintf("/account/%s/log/%s", self.Account, name)),
		LogName: name,
	}
}

// ListLogs returns a list of logs held by the account
func (self *accountImpl) ListLogs() ([]VerifiableLog, error) {
	contents, _, err := self.Client.MakeRequest("GET", fmt.Sprintf("/account/%s/logs", self.Account), nil, nil)
	if err != nil {
		return nil, err
	}

	var resp JSONLogListResponse
	err = json.Unmarshal(contents, &resp)
	if err != nil {
		return nil, err
	}

	rv := make([]VerifiableLog, len(resp.Items))
	for i, item := range resp.Items {
		rv[i] = self.VerifiableLog(item.Name)
	}

	return rv, nil
}

// ListMaps returns a list of maps held by the account
func (self *accountImpl) ListMaps() ([]VerifiableMap, error) {
	contents, _, err := self.Client.MakeRequest("GET", fmt.Sprintf("/account/%s/maps", self.Account), nil, nil)
	if err != nil {
		return nil, err
	}

	var resp JSONMapListResponse
	err = json.Unmarshal(contents, &resp)
	if err != nil {
		return nil, err
	}

	rv := make([]VerifiableMap, len(resp.Items))
	for i, item := range resp.Items {
		rv[i] = self.VerifiableMap(item.Name)
	}

	return rv, nil
}
