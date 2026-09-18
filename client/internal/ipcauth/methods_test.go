package ipcauth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoregistry"

	nbproto "github.com/netbirdio/netbird/client/proto"
)

// requestPrototypes returns a zero value of each RPC's request message, keyed by
// method name.
func requestPrototypes(t *testing.T) map[string]any {
	t.Helper()

	sd := nbproto.File_daemon_proto.Services().ByName("DaemonService")
	require.NotNil(t, sd, "DaemonService is missing from the daemon proto descriptor")

	out := make(map[string]any, sd.Methods().Len())
	for i := 0; i < sd.Methods().Len(); i++ {
		md := sd.Methods().Get(i)
		mt, err := protoregistry.GlobalTypes.FindMessageByName(md.Input().FullName())
		require.NoError(t, err, "request type for %s is not registered", md.Name())
		out[string(md.Name())] = mt.New().Interface()
	}
	return out
}

// Every RPC on DaemonService must carry an explicit policy.
func TestMethodPoliciesCoverService(t *testing.T) {
	registered := make(map[string]bool, len(methodPolicies))
	for method := range methodPolicies {
		registered[strings.TrimPrefix(method, servicePath)] = true
	}

	for _, m := range nbproto.DaemonService_ServiceDesc.Methods {
		assert.True(t, registered[m.MethodName],
			"%s has no entry in methodPolicies, add one in methods.go", m.MethodName)
		delete(registered, m.MethodName)
	}
	for _, s := range nbproto.DaemonService_ServiceDesc.Streams {
		assert.True(t, registered[s.StreamName],
			"%s has no entry in methodPolicies, add one in methods.go", s.StreamName)
		delete(registered, s.StreamName)
	}

	for stale := range registered {
		assert.Fail(t, "stale policy entry",
			"methodPolicies has %s, which DaemonService no longer defines", stale)
	}
}

// A key without the service prefix can never matched.
func TestMethodPolicyKeysAreFullMethodNames(t *testing.T) {
	for method := range methodPolicies {
		assert.True(t, strings.HasPrefix(method, servicePath),
			"%q is not a full gRPC method name and can never match a request", method)
	}
}

// TargetsProfile promises the request names a profile.
func TestTargetScopedRequestsExposeATarget(t *testing.T) {
	prototypes := requestPrototypes(t)

	for method, policy := range methodPolicies {
		if !policy.TargetsProfile {
			continue
		}
		name := strings.TrimPrefix(method, servicePath)
		msg, ok := prototypes[name]
		require.True(t, ok, "%s is marked TargetsProfile but is not a unary method on DaemonService", name)

		_, named := targetProfile(msg)
		assert.True(t, named,
			"%s is marked TargetsProfile but its request exposes neither GetHandle nor GetProfileName", name)
	}
}

// Ensure that we are not missing request that names a profile.
func TestRequestsWithATargetAreDeclared(t *testing.T) {
	// AddProfileRequest.ProfileName is the name of the profile to create. It
	// does not exist yet, so there is no owner to authorize against.
	exceptions := map[string]string{
		"AddProfile": "ProfileName names the profile to create, not one to authorize",
	}

	for name, msg := range requestPrototypes(t) {
		if _, named := targetProfile(msg); !named {
			continue
		}
		policy := methodPolicies[servicePath+name]

		if reason, excepted := exceptions[name]; excepted {
			assert.False(t, policy.TargetsProfile,
				"%s is listed as an exception (%s) but is marked TargetsProfile", name, reason)
			continue
		}
		assert.True(t, policy.TargetsProfile,
			"%s carries a profile target but is not marked TargetsProfile", name)
	}
}

// The stream interceptor runs before any message is read, so msg is nil and no
// target can be extracted.
func TestNoStreamingMethodTargetsProfile(t *testing.T) {
	for _, s := range nbproto.DaemonService_ServiceDesc.Streams {
		assert.False(t, methodPolicies[servicePath+s.StreamName].TargetsProfile,
			"%s is a stream and cannot carry a profile target", s.StreamName)
	}
}
