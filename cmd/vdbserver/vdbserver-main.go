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

	"github.com/continusec/verifiabledatastructures/api"
	"github.com/continusec/verifiabledatastructures/kvstore"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/server"
	"github.com/golang/protobuf/proto"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Please specify a config file for the server to use.")
	}

	confData, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("Error reading server configuration: %s\n", err)
	}

	conf := &pb.ServerConfig{}
	err = proto.UnmarshalText(string(confData), conf)
	if err != nil {
		log.Fatalf("Error parsing server configuration: %s\n", err)
	}

	db := &kvstore.BoltBackedService{
		Path: conf.BoltDbPath,
	}
	service := &api.LocalService{
		AccessPolicy: &api.StaticOracle{
			Config: conf.Accounts,
		},
		Mutator: &api.InstantMutator{
			Writer: db,
		},
		Reader: db,
	}

	if conf.GrpcServer {
		go server.StartGRPCServer(conf, service)
	}
	if conf.RestServer {
		go server.StartRESTServer(conf, service)
	}
	select {} // wait forever
}
