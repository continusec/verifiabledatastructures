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

package verifiabledatastructures

import (
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// StartGRPCServer starts a gRPC server given a service. Normally this service is an instance
// of LocalService.
func StartGRPCServer(conf *ServerConfig, server VerifiableDataStructuresServiceServer) {
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

	RegisterVerifiableDataStructuresServiceServer(grpcServer, server)

	log.Printf("Listening grpc on %s...", conf.GrpcListenBind)

	grpcServer.Serve(lis)
}
