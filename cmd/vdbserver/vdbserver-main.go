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

import "github.com/continusec/verifiabledatastructures/pb"
import (
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/continusec/verifiabledatastructures/api"
	"github.com/continusec/verifiabledatastructures/kvstore"
	
	"github.com/continusec/verifiabledatastructures/server"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/browser"
)

func demoMode() {
	log.Println("No configuration file specifed. We'll launch a non-persistent server and load browser on the launch page.")
	log.Println("Any account / API key / log / map name combination is allowed on this server.")

	db := &kvstore.TransientHashMapStorage{}
	service := &api.LocalService{
		AccessPolicy: &api.AnythingGoesOracle{},
		Mutator: &api.InstantMutator{
			Writer: db,
		},
		Reader: db,
	}

	bind := ":8092"
	go server.StartRESTServer(&ServerConfig{
		RestListenBind:           bind,
		InsecureServerForTesting: true,
	}, service)

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

	conf := &ServerConfig{}
	err = proto.UnmarshalText(string(confData), conf)
	if err != nil {
		log.Fatalf("Error parsing server configuration: %s\n", err)
	}

	db := &kvstore.BoltBackedService{
		Path: conf.BoltDbPath,
	}
	service := &api.LocalService{
		AccessPolicy: &api.StaticOracle{
			Policy: conf.Accounts,
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

func main() {
	if len(os.Args) != 2 {
		demoMode()
	} else {
		realMode(os.Args[1])
	}
}
