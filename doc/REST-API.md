# HTTP REST API

This documents the HTTP REST API for the Verifiable Data Structures API.

We suggest that the gRPC interface is preferred, however the REST API is convenient for demonstrations.

## Authorization

All API calls are HTTP(S) calls to your server. Unless you've configured your server to allow unauthenticated access, please ensure that an appropriate authorization header is present. This will typically look like:

```
Authorization: Key secrettoken
```

## Log Operations

### Add entry

```
POST /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry
```
Body is the leaf input for the entry. Provided as a convenience method - suggest using the `/extra` endpoint for API level access.

```
POST /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/xjson
```
Body is JSON that the server will convert to objecthash before add to a log. Provided as a convenience method. Provided as a convenience method - suggest using the `/extra` endpoint for API level access.

```
POST /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/xjson/redactable
```
Body is JSON that the server will convert to insert redactable nonces in before taking the objecthash and adding to a log. Provided as a convenience method. Provided as a convenience method - suggest using the `/extra` endpoint for API level access.

```
POST /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/extra
```
Body is JSON in the form:

```json
{"leaf_input": "<base64encodeddata>", "extra_data": "<base64encodeddata>"}
```

Where `leaf_input` is what is used as input for the Merkle Tree, and `extra_data` is stored but not otherwise processed by the server. If using redaction, specify optional `format="1"` attribute if the data is JSON and suitable for field filtering.

If the same entry (identified by unique `leaf_input`) is attempted to be added to a log more than once, the server will return the same 200 response but will not append it a second time. As such if it is require to create a new entry (for example to represent a ledger of operations), ensure that your data contains something unique (e.g. a nonce or timestamp).

### Fetch single entry

```
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/{number:[0-9]+}
```
Returns the `leaf_input` part of the log entry. Provided as a convenience method - suggest using the `/extra` endpoint for API level access.

```
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/{number:[0-9]+}/xjson
```
Returns the `extra_data` part of the log entry. Provided as a convenience method - suggest using the `/extra` endpoint for API level access.

```
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entry/{number:[0-9]+}/extra
```
Returns the JSON representation of the entry.

### Fetch multiple entries

```
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entries/{first:[0-9]+}-{last:[0-9]+}
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entries/{first:[0-9]+}-{last:[0-9]+}/xjson
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/entries/{first:[0-9]+}-{last:[0-9]+}/extra
```

All 3 return the same data, which is an array of the JSON representation of the data.

### Fetch tree hash
```
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:([0-9]+)|head}
```
Returns JSON data.

### Fetch consistency proof
```
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/consistency/{oldsize:[0-9]+}
```
For a given old and new treesize, prove the append-only nature of the log by showing providing a Merkle Tree proof that shows how the old root hash becomes the new root hash.

### Fetch inclusion proof
```
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/inclusion/h/{hash:[0-9a-f]+}
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/inclusion/s/{strentry:[0-9a-zA-Z-_]+}
GET /v2/account/{account:[0-9]+}/log/{log:[0-9a-z-_]+}/tree/{treesize:[0-9]+}/inclusion/{index:[0-9]+}
```

The primary method is the first, which look up the inclusion proof for an object by the hex-encoded Merkle Tree Leaf hash.

The second method takes a string value an input, converts it to an MTL hash on the server, then returns the same proof - this is useful for demonstrations.

The third method takes as input an index, and returns the application proof nodes for the given tree size. This is useful for demonstrations.

## Map Operations

In addition to the operations listed below, since maps have both a mutation log and a treehead log, those can be accessed with the same read-only operations as listed above, e.g. as follows:

```
GET /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/mutation/tree/head
```
```
GET /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/log/treehead/entries/0-10
```

### Set key/value

```
PUT /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/h/{key:[0-9a-f]+}
```
```
PUT /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/s/{key:[0-9a-zA-Z-_]+}
```

The `/key/s` variant takes a simple string for the key and is useful for demonstrations. For applications built on the API please instead use the `/key/h` variant that accepts a hex encoded string. e.g. `/key/s/foo` is equivalent to `/key/h/666f6f`.

### Update key/value
```
PUT /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/h/{key:[0-9a-f]+}
X-Previous-Leafhash: {previous_leaf_hash:[0-9a-f]+}
```

```
PUT /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/s/{key:[0-9a-zA-Z-_]+}
X-Previous-Leafhash: {previous_leaf_hash:[0-9a-f]+}
```

This method has the same API as a regular map set, however it takes an additional header: `X-Previous-Leafhash`. When this header is present the mutation is only applied if the current value (at time of mutation evaluation on the map) is set to the specified leaf hash that is passed in (hex-encoded). If the current value does not match, then the mutation has no effect (on the map, but still present in the mutation log).

### Delete key/value
```
DELETE /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/h/{key:[0-9a-f]+}
```
```
DELETE /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/key/s/{key:[0-9a-zA-Z-_]+}
```

Returns 200 status code to indicate that key removal has been successfully queued to be added to the corresponding mutation log and included in the map. Note that deleting a key is the equivalent of setting an empty string for that key (since by default all keys are presumed to contain empty data).

### Fetch value for key
```
GET /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:([0-9]+)|head}/key/h/{key:[0-9a-f]+}
```
```
GET /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:([0-9]+)|head}/key/s/{key:[0-9a-zA-Z-_]+}
```
Return the value for a key in the map, for a given tree size of the mutation log, typically as returned by an earlier call to retrieve a root hash for the map. Use the special value `head` to return the latest value. Additionally returns a proof that can applied to the returned value that demonstrates how to calculate the map root hash for that value. In this manner the value (or non-inclusion thereof, indicated by an empty value) can be proven to be correct for a given root hash.

The response body contains the value for the key, which will be of length 0 if no value is set, and in addition the following headers are present:

```
X-Verified-Treesize: 223131
```

The size of the tree for which the proof is valid.

```
X-Verified-Proof: 2/89cf712ba37c29c0efd289e350ea5ecc1e6640a85e7bdfc20518ebcd85e6e633
```
A map inclusion proof for a value contains up to 256 values. The `X-Verified-Proof` header is sent for each value in the audit path that is not a default value. This is approximately `log2(treesize)`. The format of this header is `<level in proof>/<hex encoded hash>;`. Note that many HTTP client libraries will concatenate multiple headers with the same name into a single value separated by commas (and this is allowed per [RFC2616](https://tools.ietf.org/html/rfc2616#section-4.2)).

### Fetch tree hash

```
GET /v2/account/{account:[0-9]+}/map/{map:[0-9a-z-_]+}/tree/{treesize:([0-9]+)|head}
```

Return the root hash for the map for a given tree size.

# Examples

The following assumes that `vdbserver` is installed.

## Log examples

Create some log entries:

```
$ curl -i --data foo http://localhost:8092/v2/account/0/log/test/entry
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:02:43 GMT
Content-Length: 61

{"leaf_hash":"HSA5+nlx9L8BocIMsqP+evRoZcqc2bhAwgY9+P7E/3U="}
```

```
$ curl -i --data bar http://localhost:8092/v2/account/0/log/test/entry
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:02:48 GMT
Content-Length: 61

{"leaf_hash":"SFkEEpvdpdG1+8a8SoKVns+5BC20TcCP6H42Cwo/JQE="}
```

```
$ curl -i --data baz http://localhost:8092/v2/account/0/log/test/entry
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:02:52 GMT
Content-Length: 61

{"leaf_hash":"sG1pWGnxBf/6X2jEuWKNWKGv9GmjxiyMdN2yr0exeO8="}
```

Fetch them:

```
$ curl -i http://localhost:8092/v2/account/0/log/test/entry/0
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Wed, 19 Apr 2017 23:03:09 GMT
Content-Length: 3

foo
```

```
$ curl -i http://localhost:8092/v2/account/0/log/test/entries/0-2
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:03:23 GMT
Content-Length: 57

{"values":[{"leaf_input":"Zm9v"},{"leaf_input":"YmFy"}]}
```

Fetch tree head:

```
$ curl -i http://localhost:8092/v2/account/0/log/test/tree/head
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:03:42 GMT
Content-Length: 75

{"tree_size":3,"root_hash":"WsgzPtL4gEb+Y5cgWyvyavq9JSti6RAZjgDIOZ0Q2PU="}
```

```
$ curl -i http://localhost:8092/v2/account/0/log/test/tree/2
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:03:45 GMT
Content-Length: 75

{"tree_size":2,"root_hash":"OShqSlUxYidR1oRbuO+0zzO+wsXz+EMNdYSHQ3GjW9o="}
```

Fetch consistency proof:

```
$ curl -i http://localhost:8092/v2/account/0/log/test/tree/2/consistency/1
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:04:01 GMT
Content-Length: 92

{"from_size":1,"tree_size":2,"audit_path":["SFkEEpvdpdG1+8a8SoKVns+5BC20TcCP6H42Cwo/JQE="]}
```

Fetch inclusion proof:

```
$ curl -i http://localhost:8092/v2/account/0/log/test/tree/2/inclusion/s/foo
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:04:15 GMT
Content-Length: 78

{"tree_size":2,"audit_path":["SFkEEpvdpdG1+8a8SoKVns+5BC20TcCP6H42Cwo/JQE="]}
```

## Map Examples

Add some values:

```
$ curl -i -X PUT --data bar http://localhost:8092/v2/account/0/map/testmap/key/s/foo
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:09:25 GMT
Content-Length: 61

{"leaf_hash":"gfFz86VjwbDKD/d5x2tekf6RitkE/dgxyjGmayBVuaw="}
```

```
$ curl -i -X PUT --data boz http://localhost:8092/v2/account/0/map/testmap/key/s/baz
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:09:39 GMT
Content-Length: 61

{"leaf_hash":"j4qHmWZFLGm1ppmrfz3SOuxN6Zen21FxA5Q1+i69Fjo="}
```

```
$ curl -i -X PUT --data b2z http://localhost:8092/v2/account/0/map/testmap/key/s/ba3
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:35:25 GMT
Content-Length: 61

{"leaf_hash":"GbrEcsRslEXv0aBBCUyYSOakae3b9xV60ESX5UFZ9P0="}
```

Retrieve a value:

```
$ curl -i http://localhost:8092/v2/account/0/map/testmap/tree/head/key/s/foo
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
X-Verified-Proof: 0/b3b798ddb6961a327d91db5af5e8d62877638d8a84d360bfffe4b2779596f5bf
X-Verified-Proof: 2/f24156884dead09f0356ddde3010958f783fc30e0549df4e79683bdf49ba0dc7
X-Verified-Treesize: 3
Date: Wed, 19 Apr 2017 23:36:00 GMT
Content-Length: 3

bar
```

Fetch a map head:

```
$ curl -i http://localhost:8092/v2/account/0/map/testmap/tree/head
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:36:20 GMT
Content-Length: 151

{"root_hash":"GfBl+c4bqJw0KpkuSMUbU5B0MAX0xBWMEbuB8I4vbCM=","mutation_log":{"tree_size":3,"root_hash":"Mak1XySVJJg6KNKA85phwxfdIAWEE5BJyX8upNt1bj0="}}
```

Retrieve entries from the mutation log:

```
$ curl -i http://localhost:8092/v2/account/0/map/testmap/log/mutation/entries/0-0
HTTP/1.1 200 OK
Content-Type: text/json
Date: Wed, 19 Apr 2017 23:36:33 GMT
Content-Length: 724

{"values":[{"leaf_input":"Ssx+XE6if0wbp2igz+DZeBw/JKW6tBX4fsBkRhtJMMI=","extra_data":"eyJ0aW1lc3RhbXAiOiIyMDE3LTA0LTIwVDA5OjA5OjI1Ljg2NTA4NjQxMisxMDowMCIsImFjdGlvbiI6InNldCIsImtleSI6IlptOXYiLCJ2YWx1ZSI6eyJsZWFmX2lucHV0IjoiWW1GeSJ9fQ==","format":1},{"leaf_input":"eJfPk4B8FoaTIkhESfcQyE4CEeLFIgpIB489xLBnHPI=","extra_data":"eyJ0aW1lc3RhbXAiOiIyMDE3LTA0LTIwVDA5OjA5OjM5Ljc2Nzg2MDAzOSsxMDowMCIsImFjdGlvbiI6InNldCIsImtleSI6IlltRjYiLCJ2YWx1ZSI6eyJsZWFmX2lucHV0IjoiWW05NiJ9fQ==","format":1},{"leaf_input":"GqU9E/RevQMF1tRRPqRuxZvT3ldkTQGBbseQ4jPeI1w=","extra_data":"eyJ0aW1lc3RhbXAiOiIyMDE3LTA0LTIwVDA5OjM1OjI1LjgyNzk0MDQzNSsxMDowMCIsImFjdGlvbiI6InNldCIsImtleSI6IlltRXoiLCJ2YWx1ZSI6eyJsZWFmX2lucHV0IjoiWWpKNiJ9fQ==","format":1}]}
```

Decoding an `extra_data` field renders:

```
{
	"timestamp": "2017-04-20T09:09:25.865086412+10:00",
	"action": "set",
	"key": "Zm9v",
	"value": {
		"leaf_input":"YmFy"
	}
}
```