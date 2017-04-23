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
	"net/http"

	"github.com/continusec/verifiabledatastructures/pb"
)

// StartRESTServer starts an HTTP REST server given a service. Normally this service is an instance
// of LocalService.
func StartRESTServer(conf *pb.ServerConfig, server pb.VerifiableDataStructuresServiceServer) error {
	if conf.InsecureServerForTesting {
		log.Println("WARNING: InsecureServerForTesting is set, your connections will not be encrypted")
	}
	log.Printf("Listening REST on %s...", conf.RestListenBind)
	if conf.InsecureServerForTesting {
		return http.ListenAndServe(conf.RestListenBind, CreateRESTHandler(server, nil))
	}
	return http.ListenAndServeTLS(conf.RestListenBind, conf.ServerCertPath, conf.ServerKeyPath, CreateRESTHandler(server, nil))
}
