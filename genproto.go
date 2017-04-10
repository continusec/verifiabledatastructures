package vdsserver

//go:generate protoc --go_out=pb -Iproto proto/server-config.proto proto/mutation.proto

/*
	Just run:

	go generate

	in this directory to generate the protos.
*/
