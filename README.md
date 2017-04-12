This repository contains a server implementation of the Continusec Verifiable Data Structures API.

It was originally written by Adam Eijdenberg (<adam@continusec.com>) and is released under the Apache 2.0 License.

Enjoy.

# Development Commands

## Re-generate proto

```bash
rm -rf pb
mkdir pb
go generate
```

## Rebuild server
```bash
go install github.com/continusec/verifiabledatastructures/cmd/vdbserver
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