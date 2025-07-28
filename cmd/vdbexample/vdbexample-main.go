package main

import (
	"context"
	"log"

	"github.com/continusec/verifiabledatastructures/mutator/instant"
	"github.com/continusec/verifiabledatastructures/oracle/policy"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/storage/bolt"
	"github.com/continusec/verifiabledatastructures/verifiable"
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
	log.Println(th.String())
}
