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
	"net"
	"net/http"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/continusec/verifiabledatastructures/api"
	"github.com/continusec/verifiabledatastructures/apife"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/golang/protobuf/proto"
)

func startGRPCServer(conf *pb.ServerConfig, server pb.VerifiableDataStructuresServiceServer) {
	lis, err := net.Listen(conf.GrpcListenProtocol, conf.GrpcListenBind)
	if err != nil {
		log.Fatalf("Error establishing server listener: %s\n", err)
	}
	var grpcServer *grpc.Server
	if conf.InsecureServerForTesting {
		log.Println("WARNING: InsecureServerForTesting is set, your connections will not be encrypted")
		grpcServer = grpc.NewServer()
	} else {
		tc, err := credentials.NewServerTLSFromFile(conf.ServerCertPath, conf.ServerKeyPath)
		if err != nil {
			log.Fatalf("Error reading server keys/certs: %s\n", err)
		}
		grpcServer = grpc.NewServer(grpc.Creds(tc))
	}

	pb.RegisterVerifiableDataStructuresServiceServer(grpcServer, server)

	log.Printf("Listening grpc on %s...", conf.GrpcListenBind)

	grpcServer.Serve(lis)
}

func startRESTServer(conf *pb.ServerConfig, server pb.VerifiableDataStructuresServiceServer) error {
	log.Printf("Listening REST on %s...", conf.RestListenBind)
	if conf.InsecureServerForTesting {
		log.Println("WARNING: InsecureServerForTesting is set, your connections will not be encrypted")
		return http.ListenAndServe(conf.RestListenBind, apife.CreateRESTHandler(server))
	}
	return http.ListenAndServeTLS(conf.RestListenBind, conf.ServerCertPath, conf.ServerKeyPath, apife.CreateRESTHandler(server))
}

func startServers(conf *pb.ServerConfig, server pb.VerifiableDataStructuresServiceServer) {
	if conf.GrpcServer {
		go startGRPCServer(conf, server)
	}
	if conf.RestServer {
		go startRESTServer(conf, server)
	}
}

func waitForever() {
	select {}
}

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

	startServers(conf, &api.LocalService{})
	waitForever()
}
