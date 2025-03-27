package logger

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// UnaryClientInterceptor logs gRPC requests using the global logrus logger
func UnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		start := time.Now()

		// og the request
		if msg, ok := req.(proto.Message); ok {
			if jsonReq, err := protojson.Marshal(msg); err == nil {
				logrus.Debugf("gRPC request initiated: method=%s, request=%s", method, jsonReq)
			} else {
				logrus.Warnf("Could not marshal gRPC request: method=%s, error=%v", method, err)
			}
		} else {
			logrus.Debugf("gRPC request initiated: method=%s, requestType=%T", method, req)
		}

		err := invoker(ctx, method, req, reply, cc, opts...)

		duration := time.Since(start)

		// log the response
		if err != nil {
			logrus.Errorf("gRPC request failed: method=%s, duration=%v, error=%v", method, duration, err)
		} else {
			if msg, ok := reply.(proto.Message); ok {
				if jsonReply, err := protojson.Marshal(msg); err == nil {
					logrus.Debugf("gRPC request succeeded: method=%s, duration=%v, response=%s", method, duration, jsonReply)
				} else {
					logrus.Warnf("Could not marshal gRPC response: method=%s, error=%v", method, err)
				}
			} else {
				logrus.Debugf("gRPC request succeeded: method=%s, duration=%v, responseType=%T", method, duration, reply)
			}
		}

		return err
	}
}
