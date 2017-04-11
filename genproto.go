package verifiabledatastructures

//go:generate protoc --go_out=plugins=grpc:pb -Iproto proto/server-config.proto proto/mutation.proto proto/api.proto

/*
	Just run:

	go generate

	in this directory to generate the protos.
*/
