This repository contains a server implementation of the Continusec Verifiable Data Structures API.

It was originally written by Adam Eijdenberg (<adam@continusec.com>) and is released under the Apache 2.0 License.

Enjoy.

# Development Commands

## Re-generate proto

```bash
rm -rf pb
mkdir pb
protoc --go_out=pb -Iproto proto/server-config.proto
```

## Rebuild server
```bash
go install github.com/continusec/vds-server/cmd/vds-server
```

## Sample config file for server

```proto
# openssl req -x509 -newkey rsa:4096 -keyout vds-key.pem -out vds-cert.pem -days 3600 -nodes -subj '/CN=localhost' -batch
# server_cert_path: "vds-cert.pem"
# server_key_path: "vds-key.pem"

listen_bind: ":8092"
insecure_http_server_for_testing: true
```