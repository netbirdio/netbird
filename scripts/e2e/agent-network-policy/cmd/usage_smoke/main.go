// usage_smoke is the e2e helper that drives the new agent-network
// gRPC RPCs (CheckLLMPolicyLimits, RecordLLMUsage) against a local
// management server. Run from the bash suite as a `go run` so the
// proto types are always in sync with the management binary the
// suite is exercising.
//
// Two subcommands today:
//   - record: invokes RecordLLMUsage with the supplied tokens / cost
//     and exits 0 on success.
//   - check:  invokes CheckLLMPolicyLimits and prints the response as
//     JSON on stdout so the bash test can assert on it via
//     jq.
//
// Auth uses the same proxy bearer-token shape the real proxy uses
// (see proxy/internal/grpc/auth.go); the bash suite reads the token
// from the e2e env (NB_PROXY_TOKEN, defaulted to the Tilt literal).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// proxyTokenCreds mirrors proxy/internal/grpc.WithProxyToken's
// PerRPCCredentials so the e2e binary can reach the gRPC service
// using the same bearer-token shape the real proxy uses. Inlined
// because the production helper lives behind /internal/.
type proxyTokenCreds struct{ token string }

func (c proxyTokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + c.token}, nil
}

// RequireTransportSecurity is false here because Tilt's management is
// plaintext on localhost — the e2e suite is the *only* caller of this
// binary, never production.
func (proxyTokenCreds) RequireTransportSecurity() bool { return false }

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)

	switch cmd {
	case "record":
		runRecord()
	case "check":
		runCheck()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: usage_smoke <record|check> [flags]")
	os.Exit(2)
}

func runRecord() {
	addr := flag.String("addr", "localhost:8080", "management gRPC address")
	token := flag.String("token", os.Getenv("NB_PROXY_TOKEN"), "proxy token")
	accountID := flag.String("account", "", "netbird account id")
	userID := flag.String("user", "", "netbird user id (optional)")
	groupID := flag.String("group", "", "netbird policy attribution group id (optional)")
	groupsCSV := flag.String("groups", "", "CSV of caller group ids (for account-rule fan-out)")
	windowSeconds := flag.Int64("window-seconds", 86_400, "window length in seconds (0 allowed when only account rules apply)")
	tokensIn := flag.Int64("tokens-in", 0, "input tokens to add")
	tokensOut := flag.Int64("tokens-out", 0, "output tokens to add")
	costUSD := flag.Float64("cost-usd", 0, "USD cost to add")
	flag.Parse()

	if strings.TrimSpace(*token) == "" {
		exitErr("--token is required (or set NB_PROXY_TOKEN)")
	}
	if strings.TrimSpace(*accountID) == "" {
		exitErr("--account is required")
	}
	var groupIDs []string
	for _, g := range strings.Split(*groupsCSV, ",") {
		g = strings.TrimSpace(g)
		if g != "" {
			groupIDs = append(groupIDs, g)
		}
	}
	if *userID == "" && *groupID == "" && len(groupIDs) == 0 {
		exitErr("at least one of --user, --group, or --groups must be set")
	}

	conn := dial(*addr, *token)
	defer conn.Close()
	client := proto.NewProxyServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.RecordLLMUsage(ctx, &proto.RecordLLMUsageRequest{
		AccountId:     *accountID,
		UserId:        *userID,
		GroupId:       *groupID,
		GroupIds:      groupIDs,
		WindowSeconds: *windowSeconds,
		TokensInput:   *tokensIn,
		TokensOutput:  *tokensOut,
		CostUsd:       *costUSD,
	})
	if err != nil {
		exitErr(fmt.Sprintf("RecordLLMUsage: %v", err))
	}
	//nolint:forbidigo // e2e helper: stdout is the contract with the bash caller
	fmt.Println("ok")
}

func runCheck() {
	addr := flag.String("addr", "localhost:8080", "management gRPC address")
	token := flag.String("token", os.Getenv("NB_PROXY_TOKEN"), "proxy token")
	accountID := flag.String("account", "", "netbird account id")
	userID := flag.String("user", "", "netbird user id (optional)")
	groupsCSV := flag.String("groups", "", "CSV of caller group ids")
	providerID := flag.String("provider", "", "agent-network provider id")
	model := flag.String("model", "gpt-4o", "upstream model identifier")
	flag.Parse()

	if strings.TrimSpace(*token) == "" {
		exitErr("--token is required (or set NB_PROXY_TOKEN)")
	}
	if strings.TrimSpace(*accountID) == "" {
		exitErr("--account is required")
	}

	var groupIDs []string
	for _, g := range strings.Split(*groupsCSV, ",") {
		g = strings.TrimSpace(g)
		if g != "" {
			groupIDs = append(groupIDs, g)
		}
	}

	conn := dial(*addr, *token)
	defer conn.Close()
	client := proto.NewProxyServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.CheckLLMPolicyLimits(ctx, &proto.CheckLLMPolicyLimitsRequest{
		AccountId:  *accountID,
		UserId:     *userID,
		GroupIds:   groupIDs,
		ProviderId: *providerID,
		Model:      *model,
	})
	if err != nil {
		exitErr(fmt.Sprintf("CheckLLMPolicyLimits: %v", err))
	}

	out, _ := json.Marshal(map[string]any{
		"decision":             resp.GetDecision(),
		"selected_policy_id":   resp.GetSelectedPolicyId(),
		"attribution_group_id": resp.GetAttributionGroupId(),
		"window_seconds":       resp.GetWindowSeconds(),
		"deny_code":            resp.GetDenyCode(),
		"deny_reason":          resp.GetDenyReason(),
	})
	//nolint:forbidigo // e2e helper: stdout is the contract with the bash caller
	fmt.Println(string(out))
}

// dial connects to the management gRPC over plaintext. The bearer
// token is sent on every RPC via PerRPCCredentials matching the wire
// format the production proxy uses.
func dial(addr, token string) *grpc.ClientConn {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(proxyTokenCreds{token: token}),
	)
	if err != nil {
		exitErr(fmt.Sprintf("dial %s: %v", addr, err))
	}
	return conn
}

func exitErr(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
