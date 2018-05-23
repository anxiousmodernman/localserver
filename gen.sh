#!/bin/bash

# Generate grpc code from protobuf
protoc grpc.proto --go_out=plugins=grpc:$GOPATH/src
