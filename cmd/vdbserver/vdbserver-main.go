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

package main

import (
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/continusec/verifiabledatastructures"
	"github.com/continusec/verifiabledatastructures/pb"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/browser"
)

func demoMode() {
	log.Println("No configuration file specifed. We'll launch a non-persistent server and load browser on the launch page.")
	log.Println("Any account / API key / log / map name combination is allowed on this server.")

	bind := ":8092"

	db := &verifiabledatastructures.TransientHashMapStorage{}
	go verifiabledatastructures.StartRESTServer(&pb.ServerConfig{
		RestListenBind:           bind,
		InsecureServerForTesting: true,
	}, (&verifiabledatastructures.LocalService{
		AccessPolicy: &verifiabledatastructures.AnythingGoesOracle{},
		Mutator: &verifiabledatastructures.InstantMutator{
			Writer: db,
		},
		Reader: db,
	}).MustCreate())

	url := "http://localhost" + bind
	log.Println("Navigate to: " + url)
	log.Println("Type ctrl-C to terminate server")

	time.Sleep(50) // should be long enough

	browser.OpenURL(url) // ignore error

	select {} // wait forever

}

func realMode(confPath string) {
	confData, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatalf("Error reading server configuration: %s\n", err)
	}

	conf := &pb.ServerConfig{}
	err = proto.UnmarshalText(string(confData), conf)
	if err != nil {
		log.Fatalf("Error parsing server configuration: %s\n", err)
	}

	db := &verifiabledatastructures.BoltBackedService{
		Path: conf.BoltDbPath,
	}
	defer db.Close() // release file locks

	service := (&verifiabledatastructures.LocalService{
		AccessPolicy: &verifiabledatastructures.StaticOracle{
			Policy: conf.Accounts,
		},
		Mutator: &verifiabledatastructures.InstantMutator{
			Writer: db,
		},
		Reader: db,
	}).MustCreate()

	if conf.GrpcServer {
		go verifiabledatastructures.StartGRPCServer(conf, service)
	}
	if conf.RestServer {
		go verifiabledatastructures.StartRESTServer(conf, service)
	}
	select {} // wait forever
}

func main() {
	if len(os.Args) != 2 {
		demoMode()
	} else {
		realMode(os.Args[1])
	}
}
