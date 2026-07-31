package llm

import (
	sharedllm "github.com/netbirdio/netbird/shared/llm"
)

// NormalizeBedrockModel strips an ARN wrapper, a cross-region inference-profile
// prefix, and the version/throughput suffix from a Bedrock model id so it
// matches the catalog/pricing key. Thin delegate to the shared implementation
// (shared/llm), which management also uses at synthesis time so both sides of
// the pricing / routing contract normalize identically.
func NormalizeBedrockModel(modelID string) string {
	return sharedllm.NormalizeBedrockModel(modelID)
}

// NormalizeVertexModel strips the "@version" suffix from a Vertex AI model id
// so it matches the catalog/pricing key. Thin delegate to shared/llm, kept
// beside NormalizeBedrockModel for the same contract reason.
func NormalizeVertexModel(modelID string) string {
	return sharedllm.NormalizeVertexModel(modelID)
}
