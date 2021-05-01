This is a Wiretrustee signal-exchange server and client library to exchange connection information between Wiretrustee Trusted Device and Wiretrustee Hub

The project uses gRPC library and defines service in protobuf file located in:
 ```proto/signal_exchange.proto```
 
 To build the project you have to do the following things.

Install protobuf version 3 (by default v3 is installed on ubuntu 20.04. On previous versions it is proto 2):
 ```
sudo apt install protoc-gen-go
sudo apt install golang-goprotobuf-dev
 ```
 
Generate gRPC code:
 ```
 protoc -I proto/ proto/signalexchange.proto --go_out=plugins=grpc:proto

 ```