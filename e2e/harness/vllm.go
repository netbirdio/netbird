//go:build e2e

package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	vllmImage = "nginx:alpine"
	vllmAlias = "vllm"
	vllmPort  = "8000/tcp"
	// VLLMModel is the served model id the mock advertises and echoes back. It
	// matches a real small model commonly served by vLLM so the provider's
	// enumerated model and the client's request line up.
	VLLMModel = "Qwen/Qwen2.5-0.5B-Instruct"
	// VLLMUnlistedModel is a second id the mock's model listing advertises but
	// no test provider enumerates, so a filtered listing is observably shorter
	// than the upstream's own.
	VLLMUnlistedModel = "Qwen/Qwen2.5-7B-Instruct"
)

// Token counts the mock reports per wire shape. Tests assert on these rather
// than on "> 0" so a response parsed with the wrong provider's parser (which
// would read a different field, or none) fails loudly instead of passing on
// a coincidental non-zero.
const (
	// VLLMChatInputTokens / VLLMChatOutputTokens ride the OpenAI usage block.
	VLLMChatInputTokens  = 11
	VLLMChatOutputTokens = 2
	// VLLMMessagesInputTokens / VLLMMessagesOutputTokens ride the Anthropic
	// usage block, whose field names the OpenAI parser cannot read.
	VLLMMessagesInputTokens  = 17
	VLLMMessagesOutputTokens = 3
)

// vllmNginxConf emulates a vLLM OpenAI-compatible server over plain HTTP (vLLM's
// default: no TLS, port 8000), and additionally answers the wire shapes the
// other catalog surfaces speak so one mock can stand in for every provider the
// proxy routes to. Running actual vLLM in CI is infeasible (GPU + multi-GB model
// download), so this stands in for the wire contract the proxy depends on.
//
// Each shape answers with its own vendor's usage block, so a response parsed
// under the wrong surface meters zero rather than passing by accident:
//
//   - /v1/chat/completions (and any unmatched path): OpenAI chat completion.
//   - /v1/messages: Anthropic Messages, snake_case usage plus a cache bucket.
//   - /model/{id}/invoke: Bedrock InvokeModel, which carries the Anthropic body.
//   - the token-counting endpoints: a count, with no usage block at all.
//
// The model listing advertises two models so a policy that authorises one
// produces an observably shorter list than the upstream's own.
const vllmNginxConf = `pid /tmp/nginx.pid;
events {}
http {
  server {
    listen 8000;
    location = /v1/models {
      default_type application/json;
      return 200 '{"object":"list","data":[{"id":"Qwen/Qwen2.5-0.5B-Instruct","object":"model","owned_by":"vllm"},{"id":"Qwen/Qwen2.5-7B-Instruct","object":"model","owned_by":"vllm"}]}';
    }
    location = /v1/messages {
      default_type application/json;
      return 200 '{"id":"msg_e2e","type":"message","role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"pong"}],"stop_reason":"end_turn","usage":{"input_tokens":17,"output_tokens":3,"cache_read_input_tokens":5}}';
    }
    location = /v1/messages/count_tokens {
      default_type application/json;
      return 200 '{"input_tokens":7}';
    }
    location ~ ^/model/.+/invoke$ {
      default_type application/json;
      return 200 '{"id":"msg_e2e_bedrock","type":"message","role":"assistant","content":[{"type":"text","text":"pong"}],"stop_reason":"end_turn","usage":{"input_tokens":17,"output_tokens":3,"cache_read_input_tokens":5}}';
    }
    location ~ ^/model/.+/count-tokens$ {
      default_type application/json;
      return 200 '{"inputTokens":9}';
    }
    location = /api/hello {
      return 200;
    }
    location / {
      default_type application/json;
      return 200 '{"id":"chatcmpl-e2e-vllm","object":"chat.completion","created":1700000000,"model":"Qwen/Qwen2.5-0.5B-Instruct","choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":2,"total_tokens":13}}';
    }
  }
}
`

// VLLM is a mock vLLM OpenAI-compatible server on the combined server's network,
// reachable at http://vllm:8000. A "vllm" provider points at it to exercise the
// proxy's support for self-hosted OpenAI-compatible backends.
type VLLM struct {
	container testcontainers.Container
	workDir   string
	// URL is the upstream URL the vllm provider points at (http://<alias>:8000).
	URL string
}

// StartVLLM runs the mock vLLM server on the shared network over plain HTTP.
func StartVLLM(ctx context.Context, c *Combined) (*VLLM, error) {
	workDir, err := os.MkdirTemp("/tmp", "nb-e2e-vllm-*")
	if err != nil {
		return nil, fmt.Errorf("create vllm work dir: %w", err)
	}
	// Widen so the (non-root worker) nginx container can traverse the bind mount.
	if err := os.Chmod(workDir, 0o755); err != nil { //nolint:gosec // throwaway e2e config dir
		return nil, fmt.Errorf("chmod vllm dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "nginx.conf"), []byte(vllmNginxConf), 0o644); err != nil { //nolint:gosec // non-secret e2e config
		return nil, fmt.Errorf("write nginx conf: %w", err)
	}

	req := testcontainers.ContainerRequest{
		Image:          vllmImage,
		ExposedPorts:   []string{vllmPort},
		Networks:       []string{c.network.Name},
		NetworkAliases: map[string][]string{c.network.Name: {vllmAlias}},
		Cmd:            []string{"nginx", "-c", "/conf/nginx.conf", "-g", "daemon off;"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Binds = append(hc.Binds, workDir+":/conf:ro")
		},
		WaitingFor: wait.ForListeningPort(vllmPort).WithStartupTimeout(60 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		_ = os.RemoveAll(workDir)
		return nil, fmt.Errorf("start vllm container: %w", err)
	}

	return &VLLM{container: ctr, workDir: workDir, URL: "http://" + vllmAlias + ":8000"}, nil
}

// Logs returns the vLLM container logs, for diagnostics on failure.
func (v *VLLM) Logs(ctx context.Context) string {
	return containerLogs(ctx, v.container)
}

// Terminate stops the vLLM container and cleans its work dir.
func (v *VLLM) Terminate(ctx context.Context) error {
	var err error
	if v.container != nil {
		err = v.container.Terminate(ctx)
	}
	if v.workDir != "" {
		_ = os.RemoveAll(v.workDir)
	}
	return err
}
