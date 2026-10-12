package modeldiscovery

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	sharedllm "github.com/netbirdio/netbird/shared/llm"
)

// listedModel is one entry lifted out of a vendor listing before the catalog
// is consulted about it.
type listedModel struct {
	id    string
	label string
}

// parseListing extracts model ids from a vendor listing. Each vendor invented
// its own envelope, and the shape is declared by the catalog rather than
// sniffed, so a vendor that changes shape fails loudly instead of silently
// returning nothing.
func parseListing(shape catalog.ListingShape, body []byte) ([]listedModel, error) {
	switch shape {
	case catalog.ShapeOpenAIData:
		return parseOpenAIData(body)
	case catalog.ShapeBedrockInferenceProfiles:
		return parseBedrockInferenceProfiles(body)
	case catalog.ShapeVertexPublisherModels:
		return parseVertexPublisherModels(body)
	default:
		return nil, fmt.Errorf("no parser for listing shape %q", shape)
	}
}

// parseOpenAIData reads {"data":[{"id":…}]}, which OpenAI defined and
// Anthropic adopted. Anthropic additionally supplies display_name.
func parseOpenAIData(body []byte) ([]listedModel, error) {
	var doc struct {
		Data []struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: decode model listing: %w", ErrUnparseableListing, err)
	}
	out := make([]listedModel, 0, len(doc.Data))
	for _, entry := range doc.Data {
		out = append(out, listedModel{id: entry.ID, label: entry.DisplayName})
	}
	return out, nil
}

// parseBedrockInferenceProfiles reads
// {"inferenceProfileSummaries":[{"inferenceProfileId":…}]}.
//
// The profile id is taken verbatim because its region prefix (eu., us.,
// global.) is what makes it invocable, and it is not derivable from the
// configured region — an account in one region legitimately holds global.*
// profiles alongside its regional ones.
//
// Only ACTIVE profiles are offered: AWS reports others, and registering one
// would produce a model that routes inside NetBird and fails at AWS.
func parseBedrockInferenceProfiles(body []byte) ([]listedModel, error) {
	var doc struct {
		Summaries []struct {
			ID     string `json:"inferenceProfileId"`
			Name   string `json:"inferenceProfileName"`
			Status string `json:"status"`
		} `json:"inferenceProfileSummaries"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: decode inference-profile listing: %w", ErrUnparseableListing, err)
	}
	out := make([]listedModel, 0, len(doc.Summaries))
	for _, entry := range doc.Summaries {
		if entry.Status != "" && !strings.EqualFold(entry.Status, "ACTIVE") {
			continue
		}
		out = append(out, listedModel{id: entry.ID, label: entry.Name})
	}
	return out, nil
}

// parseVertexPublisherModels reads {"publisherModels":[{"name":…}]}, where
// name is a resource path ("publishers/anthropic/models/claude-3-opus") and
// the version lives in a separate field.
//
// Vertex addresses a model as "<id>@<version>" on the rawPredict path, so the
// two are joined here: reporting the bare name would hand the operator an id
// that looks usable and is not.
func parseVertexPublisherModels(body []byte) ([]listedModel, error) {
	var doc struct {
		Models []struct {
			Name      string `json:"name"`
			VersionID string `json:"versionId"`
		} `json:"publisherModels"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: decode publisher-model listing: %w", ErrUnparseableListing, err)
	}
	out := make([]listedModel, 0, len(doc.Models))
	for _, entry := range doc.Models {
		id := entry.Name
		if slash := strings.LastIndex(id, "/"); slash >= 0 {
			id = id[slash+1:]
		}
		if id == "" {
			continue
		}
		label := id
		if entry.VersionID != "" {
			id += "@" + entry.VersionID
		}
		out = append(out, listedModel{id: id, label: label})
	}
	return out, nil
}

// normalizeForPricing maps a vendor's wire id onto the key the catalog prices
// it under. It mirrors the synthesiser's normalizePricingModelID: the two must
// agree, or a model reported here as priced would meter at the default rate
// instead of the operator's.
func normalizeForPricing(catalogProviderID, modelID string) string {
	switch {
	case catalog.IsBedrockPathStyle(catalogProviderID):
		return sharedllm.NormalizeBedrockModel(modelID)
	case catalog.IsVertexPathStyle(catalogProviderID):
		return sharedllm.NormalizeVertexModel(modelID)
	default:
		return modelID
	}
}
