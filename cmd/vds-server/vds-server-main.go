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
	"net/http"
	"os"

	"github.com/continusec/vds-server/apife"
	"github.com/continusec/vds-server/kvstore"
	"github.com/continusec/vds-server/pb"
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

	bbs := &kvstore.BoltBackedService{
		Path:     conf.BoltDbPath,
		Accounts: conf.Accounts,
	}
	err = bbs.Init()
	if err != nil {
		log.Fatalf("Error initializing BoltBackedService: %s\n", err)
	}
	apiHandler := apife.CreateHandler(bbs)

	log.Printf("Listening on %s...", conf.ListenBind)
	if conf.InsecureHttpServerForTesting {
		log.Println("WARNING: InsecureHttpServerForTesting is set, your connections will not be encrypted")
		err = http.ListenAndServe(conf.ListenBind, apiHandler)
	} else {
		err = http.ListenAndServeTLS(conf.ListenBind, conf.ServerCertPath, conf.ServerKeyPath, apiHandler)
	}
	if err != nil {
		log.Fatalf("Errors serving TLS: %s\n", err)
	}
}
