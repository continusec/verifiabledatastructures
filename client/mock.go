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

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

type proxyAndRecordHandler struct {
	Host                  string
	InHeaders, OutHeaders []string
	Dir                   string
	Sequence              int
	FailOnMissing         bool
	WhackNextRequest      bool
}

type savedResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

type savedRequest struct {
	URL     string
	Method  string
	Headers map[string][]string
	Body    []byte
}

func (us *savedRequest) Equals(them *savedRequest) bool {
	return reflect.DeepEqual(us, them)
}

type savedPair struct {
	Request  *savedRequest
	Response *savedResponse
}

func filePathForSeq(path string, seq int) string {
	return filepath.Join(path, fmt.Sprintf("%04d.response", seq))
}

func (s *savedPair) Write(path string, seq int) error {
	fi, err := os.Create(filePathForSeq(path, seq))
	if err != nil {
		return err
	}
	err = json.NewEncoder(fi).Encode(s)
	if err != nil {
		return err
	}
	fi.Close()
	return nil
}

func loadSavedIfThere(path string, seq int) (*savedPair, error) {
	fi, err := os.Open(filePathForSeq(path, seq))
	if err != nil {
		return nil, err
	}
	defer fi.Close()
	var rv savedPair
	err = json.NewDecoder(fi).Decode(&rv)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

func saveRequest(r *http.Request, altHost string, headerFilter []string) (*savedRequest, error) {
	url := r.URL.String()
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}
	url = altHost + url[strings.Index(url, "/"):]

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	headers := make(map[string][]string)
	for _, h := range headerFilter {
		canon := http.CanonicalHeaderKey(h)
		z, ok := r.Header[canon]
		if ok {
			headers[canon] = z
		}
	}

	return &savedRequest{
		Method:  r.Method,
		URL:     url,
		Headers: headers,
		Body:    body,
	}, nil
}

func saveResponse(resp *http.Response, headerFilter []string) (*savedResponse, error) {
	contents, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	headers := make(map[string][]string)
	for _, h := range headerFilter {
		canon := http.CanonicalHeaderKey(h)
		z, ok := resp.Header[canon]
		if ok {
			headers[canon] = z
		}
	}

	return &savedResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       contents,
	}, nil
}

func (s *proxyAndRecordHandler) writeResponse(saved *savedResponse, w http.ResponseWriter) {
	for k, vs := range saved.Headers {
		w.Header()[k] = vs
	}
	w.Header().Set("access-control-allow-origin", "*")
	w.Header().Set("access-control-expose-headers", strings.Join(s.OutHeaders, ","))
	w.WriteHeader(saved.StatusCode)
	w.Write(saved.Body)
}

func sendSavedRequest(savedReq *savedRequest, headerIn, headerOut []string) (*savedResponse, error) {
	req, err := http.NewRequest(savedReq.Method, savedReq.URL, bytes.NewReader(savedReq.Body))
	if err != nil {
		return nil, err
	}

	for _, h := range headerIn {
		canon := http.CanonicalHeaderKey(h)
		req.Header[canon] = savedReq.Headers[canon]
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	return saveResponse(resp, headerOut)
}

func (s *proxyAndRecordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() { s.WhackNextRequest = false }()

	// Special case CORS for Javascript client
	if r.Method == "OPTIONS" {
		w.Header().Set("access-control-allow-headers", strings.Join(s.InHeaders, ","))
		w.Header().Set("access-control-expose-headers", strings.Join(s.OutHeaders, ","))
		w.Header().Set("access-control-allow-origin", "*")
		w.Header().Set("access-control-allow-methods", "PUT,POST,GET,DELETE")
		w.WriteHeader(200)
		return
	}
	canonReq, err := saveRequest(r, s.Host, s.InHeaders)
	if err != nil {
		fmt.Println(s.Sequence, "Error saving request:", err)
		return
	}
	xavedPair, err := loadSavedIfThere(s.Dir, s.Sequence)
	if err != nil {
		if s.FailOnMissing {
			fmt.Println(s.Sequence, "Error loading response:", err)
			return
		}
		fmt.Println(s.Sequence, "Fetching", canonReq.URL)
		sr, err := sendSavedRequest(canonReq, s.InHeaders, s.OutHeaders)
		if err != nil {
			fmt.Println(s.Sequence, "Error receiving response:", err)
			return
		}
		xavedPair = &savedPair{
			Request:  canonReq,
			Response: sr,
		}
		err = xavedPair.Write(s.Dir, s.Sequence)
		if err != nil {
			fmt.Println(s.Sequence, "Error saving response:", err)
			return
		}
	} else {
		fmt.Println(s.Sequence, "From cache", canonReq.URL)
	}
	if !xavedPair.Request.Equals(canonReq) {
		if s.WhackNextRequest {
			fmt.Println(s.Sequence, "Overwriting request")
			xavedPair.Request = canonReq
			err = xavedPair.Write(s.Dir, s.Sequence)
			if err != nil {
				fmt.Println(s.Sequence, "Error saving response:", err)
				return
			}
		} else {
			fmt.Println(s.Sequence, "Bad request, got ", canonReq)
			fmt.Println(s.Sequence, "wanted           ", xavedPair.Request)
			return
		}
	}

	s.writeResponse(xavedPair.Response, w)
	s.IncrementSequence()
}

func (s *proxyAndRecordHandler) IncrementSequence() {
	s.Sequence++
}

func runMockServer(hostport string, pr *proxyAndRecordHandler) {
	http.ListenAndServe(hostport, pr)
}
