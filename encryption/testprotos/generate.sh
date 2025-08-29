#!/bin/bash
protoc -I testprotos/ testprotos/testproto.proto --go_out=.