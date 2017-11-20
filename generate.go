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

/*
Package verifiabledatastructures provides append-only, verifiable logs and maps. Both a client, server and
embedded options are provided, along with various data storage methods.

This is an early release of the open-source offering, and APIs are subject to change.
If you are using this library, please drop us a note at support@continusec.com so that we
can work with you on any API changes.

To interact with logs and maps, you will first need to get a reference to the low-level
API which is the set of functions defined in pb.VerifiableDataStructuresServiceServer.

Running as embedded instance

Run your own embedded instance:

	// Create an in-memory, non-persistent database, suitable for tests
	db := &memory.TransientStorage{}

	// Create a service object with no permission checking, and synchronous mutations
	service := (&verifiable.Service{
		AccessPolicy: policy.Open,
		Mutator:      &instant.Mutator{Writer: db},
		Reader:       db,
	}).MustCreate()

Connecting to a server

Connect to a remote server (example below uses grpc.Client, see also httprest.Client):

	// Connect to remote GRPC server
	service := (&grpc.Client{
		Address: "verifiabledatastructures.example.com:8081",
	}).MustDial()

Running your own server

To run your own server, simply take a pb.VerifiableDataStructuresServiceServer as created
by verifiable.Service above, and expose like follows:

	grpc.StartServer(&pb.ServerConfig{
		InsecureServerForTesting: true,
		GrpcListenBind:           ":8081",
		GrpcListenProtocol:       "tcp4",
	}, service)

Using the service

Once you have a service object, whether it is local or remote, we recommend that you wrap
it using the higher level Client object:

	client := &verifiable.Client{
		Service: service,
	}

Note that currently accounts, logs and maps are all created lazily, there is no need to
explicitly create these.

To add entries into a log (ctx can be any valid context, e.g. context.TODO() if unsure):

	promise, err := client.Account("0", "").VerifiableLog().Add(ctx, &pb.LeafData{
		LeafInput: []byte("foo"),
	})

See the documentation for verifiable.Log and verifiable.Map for all operations.

Other storage mechanisms

bolt.Storage:

	// Save logs and maps to data directory using embedded boltdb database
	db := &bolt.Storage{
		Path: "/path/to/database/dir","
	}
	defer db.Close() // Releases file locks

	// pass to LocalService in the same manner as above, e.g.
	service := (&verifiable.Service{
		AccessPolicy: policy.Open,
		Mutator:      &instant.Mutator{Writer: db},
		Reader:       db,
	}).MustCreate()

Other mutation mechanisms

batch.Mutator:

	// performs mutations asynchronously in batches - experimental
	service := (&verifiable.Service{
		AccessPolicy: policy.Open,
		Mutator: (&batch.Mutator{
			Writer:     db,
			BatchSize:  1000,
			BufferSize: 100000,
			Timeout:    time.Millisecond * 10,
		}).MustCreate(),
		Reader:       db,
	}).MustCreate()

Other authorization policies

policy.Static:

	// actually does permission checks, based on static config, e.g.
	service := (&verifiable.Service{
		Mutator:      &instant.Mutator{Writer: db},
		Reader:       db,
		AccessPolicy: &policy.Static{
			Policy: []*pb.ResourceAccount{
				{
					Id: "0",
					Policy: []*pb.AccessPolicy{
						{
							NameMatch:     "foo",
							Permissions:   []pb.Permission{pb.Permission_PERM_ALL_PERMISSIONS},
							ApiKey:        "secret",
							AllowedFields: []string{"*"},
						},
						{
							NameMatch:     "f*",
							Permissions:   []pb.Permission{pb.Permission_PERM_LOG_READ_ENTRY},
							ApiKey:        "*",
							AllowedFields: []string{"name"},
						},
					},
				},
			},
		},
	}).MustCreate()

Each of the above is interchangeable with others that implement the correct interface.

Examples

Here is a full example of using verifiabledatastructures as an embedded storage layer in your application:

	package main

	import (
		"context"
		"log"

		"github.com/continusec/verifiabledatastructures/mutator/instant"
		"github.com/continusec/verifiabledatastructures/oracle/policy"
		"github.com/continusec/verifiabledatastructures/pb"
		"github.com/continusec/verifiabledatastructures/storage/bolt"
		"github.com/continusec/verifiabledatastructures/verifiable"
		"github.com/golang/protobuf/proto"
	)

	func main() {
		// Create a pointer to a data storage layer, here we persist to disk using Bolt
		db := &bolt.Storage{
			Path: "/path/to/directory/to/store/data",
		}
		defer db.Close() // Releases file locks

		// Create an instance of the service
		service := (&verifiable.Service{
			// Allow access to everything
			AccessPolicy: policy.Open,

			// Read data from our database
			Reader: db,

			// Apply mutations synchronously
			Mutator: &instant.Mutator{
				Writer: db,
			},
		}).MustCreate()

		// Create a client to directly call the service, no need to stand up a server
		client := &verifiable.Client{
			Service: service,
		}

		// Get a pointer to a log
		vlog := client.Account("0", "").VerifiableLog("foo")

		// Create a context (not currently used)
		ctx := context.Background()

		// Add something to it
		_, err := vlog.Add(ctx, &pb.LeafData{
			LeafInput: []byte("bar"),
		})
		if err != nil {
			log.Fatal(err)
		}

		// Print tree head
		th, err := vlog.TreeHead(ctx, verifiable.Head)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(proto.CompactTextString(th))
	}

*/

//go:generate protoc --go_out=plugins=grpc:../../.. -Iproto proto/api.proto proto/configuration.proto proto/storage.proto
//go:generate go-bindata -pkg assets -o assets/assets.go assets/static/

package verifiabledatastructures
