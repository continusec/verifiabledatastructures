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
	"encoding/json"

	"github.com/continusec/objecthash"
)

type ObjectHashEntryFormat struct {
	Redactable bool
	Filter     string
	Data       []byte

	bytesForLeafHash []byte
	bytesToStore     []byte
}

func (self *ObjectHashEntryFormat) BytesForLeafHash() ([]byte, error) {
	if self.bytesForLeafHash == nil {
		bb, err := self.BytesToStoreOff()
		if err != nil {
			return nil, err
		}

		var o interface{}
		err = json.Unmarshal(bb, &o)
		if err != nil {
			return nil, ErrInvalidJSON
		}

		self.bytesForLeafHash, err = objecthash.ObjectHash(o)
		if err != nil {
			return nil, err
		}
	}
	return self.bytesForLeafHash, nil
}

func (self *ObjectHashEntryFormat) BytesToStoreOff() ([]byte, error) {
	if self.bytesToStore == nil {
		if self.Redactable {
			var o interface{}
			err := json.Unmarshal(self.Data, &o)
			if err != nil {
				return nil, ErrInvalidJSON
			}

			o, err = objecthash.Redactable(o)
			if err != nil {
				return nil, err
			}

			self.bytesToStore, err = json.Marshal(o)
			if err != nil {
				return nil, err
			}
		} else {
			self.bytesToStore = self.Data
		}
	}
	return self.bytesToStore, nil
}

/* Idempotent */
func (self *ObjectHashEntryFormat) RetrieveBytes(dbe DatastoreBlobEntry) ([]byte, error) {
	rv, err := dbe.Data()
	if err != nil {
		return nil, err
	}
	if self.Filter != "*" {
		var o interface{}
		err := json.Unmarshal(rv, &o)
		if err != nil {
			return nil, ErrInvalidJSON
		}

		o, err = objecthash.Filtered(o, self.Filter)
		if err != nil {
			return nil, err
		}

		rv, err = json.Marshal(o)
		if err != nil {
			return nil, err
		}
	}
	if rv == nil {
		return nil, ErrInvalidJSON
	}
	return rv, nil
}
