**This is pre-release, not ready for real use yet, feedback and bug reports welcome though!**

This repository contains a client, server, and embeddable library implementation of the Continusec Verifiable Data Structures API.

It was written by Adam Eijdenberg (<adam@continusec.com>) and is released under the Apache 2.0 License.

Please see the godoc for information on how to use the libraries: <https://godoc.org/github.com/continusec/verifiabledatastructures>

See the [HTTP REST API doc](./doc/REST-API.md), for examples using the REST API.


# Quickstart

```bash
go get -u github.com/continusec/verifiabledatastructures/cmd/vdbserver
vdbserver
```

# Development Commands

The following commands are useful for those working with the source.

## Re-generate proto and asset files

```bash
go generate
```

(will need `go get -u github.com/jteeuwen/go-bindata/... github.com/golang/protobuf/protoc-gen-go`)

## Rebuild server
```bash
go install github.com/continusec/verifiabledatastructures/cmd/vdbserver
```

## Run tests
```bash
go test
```

## Sample config file for server

```proto
# openssl req -x509 -newkey rsa:4096 -keyout vds-key.pem -out vds-cert.pem -days 3600 -nodes -subj '/CN=localhost' -batch
# server_cert_path: "vds-cert.pem"
# server_key_path: "vds-key.pem"

rest_server: true
rest_listen_bind: ":8092"

grpc_server: true
grpc_listen_bind: ":8090"
grpc_listen_protocol: "tcp4"

insecure_server_for_testing: true

# Bolt DB path:
bolt_db_path: "."

# Accounts supported by this server
accounts: <
    id: "1234"
    policy: <
        api_key: "secret"
        name_match: "*"
        allowed_fields: "*"
        permissions: PERM_ALL_PERMISSIONS
    >
>
```