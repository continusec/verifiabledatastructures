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

package client

import (
	"crypto/tls"
	"crypto/x509"
	"log"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/continusec/verifiabledatastructures/pb"
)

type GRPCClientConfig struct {
	NoGrpcSecurity bool   // if set, we ignore everything
	CertDer        []byte // if set, we use this

	Address string
}

func (g *GRPCClientConfig) Dial() (pb.VerifiableDataStructuresServiceServer, error) {
	var dialOptions []grpc.DialOption
	if g.NoGrpcSecurity {
		log.Println("WARNING: Disabling TLS  when connecting to gRPC server")
		dialOptions = append(dialOptions, grpc.WithInsecure())
	} else if len(g.CertDer) != 0 {
		// use baked in cert
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM([]byte(g.CertDer)) {
			return nil, ErrInternalError
		}
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: cp})))
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))) // uses the system CA pool
	}

	conn, err := grpc.Dial(g.Address, dialOptions...)
	if err != nil {
		return nil, err
	}

	return &wrapSillyClientAsServer{
		Client: pb.NewVerifiableDataStructuresServiceClient(conn),
	}, nil
}

type wrapSillyClientAsServer struct {
	Client pb.VerifiableDataStructuresServiceClient
}

func (w *wrapSillyClientAsServer) LogAddEntry(ctx context.Context, r *pb.LogAddEntryRequest) (*pb.LogAddEntryResponse, error) {
	return w.Client.LogAddEntry(ctx, r)
}

func (w *wrapSillyClientAsServer) LogFetchEntries(ctx context.Context, r *pb.LogFetchEntriesRequest) (*pb.LogFetchEntriesResponse, error) {
	return w.Client.LogFetchEntries(ctx, r)
}

func (w *wrapSillyClientAsServer) LogTreeHash(ctx context.Context, r *pb.LogTreeHashRequest) (*pb.LogTreeHashResponse, error) {
	return w.Client.LogTreeHash(ctx, r)
}

func (w *wrapSillyClientAsServer) LogInclusionProof(ctx context.Context, r *pb.LogInclusionProofRequest) (*pb.LogInclusionProofResponse, error) {
	return w.Client.LogInclusionProof(ctx, r)
}

func (w *wrapSillyClientAsServer) LogConsistencyProof(ctx context.Context, r *pb.LogConsistencyProofRequest) (*pb.LogConsistencyProofResponse, error) {
	return w.Client.LogConsistencyProof(ctx, r)
}

func (w *wrapSillyClientAsServer) MapSetValue(ctx context.Context, r *pb.MapSetValueRequest) (*pb.MapSetValueResponse, error) {
	return w.Client.MapSetValue(ctx, r)
}

func (w *wrapSillyClientAsServer) MapGetValue(ctx context.Context, r *pb.MapGetValueRequest) (*pb.MapGetValueResponse, error) {
	return w.Client.MapGetValue(ctx, r)
}

func (w *wrapSillyClientAsServer) MapTreeHash(ctx context.Context, r *pb.MapTreeHashRequest) (*pb.MapTreeHashResponse, error) {
	return w.Client.MapTreeHash(ctx, r)
}
