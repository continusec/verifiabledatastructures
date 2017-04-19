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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"

	"golang.org/x/net/context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/continusec/verifiabledatastructures/pb"
)

var (
	// ErrNoCertsFound is returned when no certificates are found in the specifed file
	ErrNoCertsFound = errors.New("no certificates found")
)

// GRPCClient provides a way to access a remote Verifiable Data Structures API
// using gRPC. This is preferred over the REST server/client.
type GRPCClient struct {
	// NoGrpcSecurity if set will disable TLS for this connection
	NoGrpcSecurity bool

	// CertDer is an ASN.1 DER X.509 certificate that the certificate presented by the server
	// must be signed by. This can be either a self-signed, or private CA cert.
	// If not set, the system CA pool is used.
	CertDer []byte

	// Address of the server to connect to, e.g. "localhost:8080"
	Address string
}

// Dial connects to the server and returns an object to communicate with it.
// Most users will wrap this with the higher-level API.
func (g *GRPCClient) Dial() (pb.VerifiableDataStructuresServiceServer, error) {
	var dialOptions []grpc.DialOption
	if g.NoGrpcSecurity {
		log.Println("WARNING: Disabling TLS  when connecting to gRPC server")
		dialOptions = append(dialOptions, grpc.WithInsecure())
	} else if len(g.CertDer) != 0 {
		// use baked in cert
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM([]byte(g.CertDer)) {
			return nil, ErrNoCertsFound
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
