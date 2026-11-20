//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/internal/agentnetwork/harness"
	"github.com/netbirdio/netbird/client/proto"
)

// Harness setup statuses, as the frontend matches them.
const (
	harnessConfigured    = "configured"
	harnessEdited        = "edited"
	harnessNotConfigured = "not_configured"
)

// AgentNetworkHarness is a coding agent the GUI can point at Agent Networks.
// Status is "configured", "edited" (NetBird's keys were changed since, or the
// file no longer parses) or "not_configured". Providers lists the providers
// this harness can use, empty unless the daemon reports the "ok" state.
type AgentNetworkHarness struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Status    string            `json:"status"`
	Files     []string          `json:"files"`
	Providers []HarnessProvider `json:"providers"`
}

// HarnessProvider is a provider a harness can use. DefaultModel is the one
// the picker starts on; empty leaves the choice to the harness.
type HarnessProvider struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Models             []string `json:"models"`
	AllModelsAllowed   bool     `json:"allModelsAllowed"`
	DefaultModel       string   `json:"defaultModel"`
	NeedsVertexProject bool     `json:"needsVertexProject"`
}

// HarnessSetup is what the user picked in the setup dialog. An empty Model
// leaves the choice to the harness.
type HarnessSetup struct {
	Harness       string `json:"harness"`
	Provider      string `json:"provider"`
	Model         string `json:"model"`
	VertexProject string `json:"vertexProject"`
}

// HarnessPlan is the per-key preview of a setup or undo. When a file cannot
// be edited safely, Unparseable names it, Changes is empty, and Snippets
// holds the settings to add by hand, one per file.
type HarnessPlan struct {
	Changes     []HarnessChange  `json:"changes"`
	Conflict    bool             `json:"conflict"`
	Pending     bool             `json:"pending"`
	Unparseable string           `json:"unparseable"`
	Snippets    []HarnessSnippet `json:"snippets"`
	Backups     []string         `json:"backups"`
}

// HarnessChange is one key a plan touches. Action is "set", "restore" or
// "keep". Before and After are JSON values, empty when the key is absent.
// Conflict marks a set over a value NetBird did not write.
type HarnessChange struct {
	File     string `json:"file"`
	Key      string `json:"key"`
	Action   string `json:"action"`
	Before   string `json:"before"`
	After    string `json:"after"`
	Conflict bool   `json:"conflict"`
}

// HarnessSnippet is the content to paste into a file by hand.
type HarnessSnippet struct {
	File    string `json:"file"`
	Content string `json:"content"`
}

// Harnesses lists the supported harnesses with their setup status. The
// engine runs in this process, as the user, so it edits the user's files.
func (s *AgentNetwork) Harnesses(ctx context.Context) ([]AgentNetworkHarness, error) {
	env, err := s.harnessEnv()
	if err != nil {
		return nil, err
	}
	rec, err := harness.LoadRecord(env.RecordPath)
	if err != nil {
		return nil, fmt.Errorf("read setup record: %w", err)
	}
	// Status and undo work without the daemon, so a failed lookup only
	// leaves the provider lists empty.
	info, infoErr := s.setupInfo(ctx)

	out := make([]AgentNetworkHarness, 0, len(harness.All()))
	for _, def := range harness.All() {
		h := AgentNetworkHarness{
			ID:        def.ID,
			Name:      def.Name,
			Status:    harnessStatus(harness.Status(def.ID, rec)),
			Files:     make([]string, 0, len(def.Files)),
			Providers: []HarnessProvider{},
		}
		for _, f := range def.Files {
			h.Files = append(h.Files, f.Path(env))
		}
		if infoErr == nil {
			h.Providers = harnessProviders(def, info.GetProviders())
		}
		out = append(out, h)
	}
	return out, nil
}

// PlanHarness previews a setup without writing anything.
func (s *AgentNetwork) PlanHarness(ctx context.Context, req HarnessSetup) (HarnessPlan, error) {
	def, settings, env, err := s.renderHarness(ctx, req)
	if err != nil {
		return HarnessPlan{}, err
	}
	s.harnessMu.Lock()
	defer s.harnessMu.Unlock()
	rec, err := harness.LoadRecord(env.RecordPath)
	if err != nil {
		return HarnessPlan{}, fmt.Errorf("read setup record: %w", err)
	}
	plan, err := harness.NewPlan(def.ID, settings, rec, false)
	var unparseable *harness.UnparseableError
	if errors.As(err, &unparseable) {
		return snippetPlan(unparseable.File, settings)
	}
	if plan == nil {
		return HarnessPlan{}, err
	}
	out := planFromEngine(plan)
	out.Conflict = errors.Is(err, harness.ErrConflict)
	return out, nil
}

// ApplyHarness writes a setup. It re-plans against the files as they are
// now; force replaces keys holding values NetBird did not write.
func (s *AgentNetwork) ApplyHarness(ctx context.Context, req HarnessSetup, force bool) (HarnessPlan, error) {
	def, settings, env, err := s.renderHarness(ctx, req)
	if err != nil {
		return HarnessPlan{}, err
	}
	s.harnessMu.Lock()
	defer s.harnessMu.Unlock()
	rec, err := harness.LoadRecord(env.RecordPath)
	if err != nil {
		return HarnessPlan{}, fmt.Errorf("read setup record: %w", err)
	}
	plan, err := harness.NewPlan(def.ID, settings, rec, force)
	if err != nil {
		return HarnessPlan{}, err
	}
	return applyPlan(plan, rec, env)
}

// UndoHarness restores every key NetBird wrote for a harness. A key the user
// changed since is left alone and reported as "keep".
func (s *AgentNetwork) UndoHarness(id string) (HarnessPlan, error) {
	def, err := harness.Lookup(id)
	if err != nil {
		return HarnessPlan{}, err
	}
	env, err := s.harnessEnv()
	if err != nil {
		return HarnessPlan{}, err
	}
	s.harnessMu.Lock()
	defer s.harnessMu.Unlock()
	rec, err := harness.LoadRecord(env.RecordPath)
	if err != nil {
		return HarnessPlan{}, fmt.Errorf("read setup record: %w", err)
	}
	plan, err := harness.NewPlan(def.ID, nil, rec, false)
	if err != nil {
		return HarnessPlan{}, err
	}
	return applyPlan(plan, rec, env)
}

func applyPlan(plan *harness.Plan, rec *harness.Record, env harness.Env) (HarnessPlan, error) {
	out := planFromEngine(plan)
	backups, err := plan.Apply(rec, env.RecordPath, time.Now())
	out.Backups = append(out.Backups, backups...)
	return out, err
}

// setupInfo returns the daemon's view, refusing every state but OK.
func (s *AgentNetwork) setupInfo(ctx context.Context) (*proto.GetAgentNetworkInfoResponse, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return nil, err
	}
	info, err := cli.GetAgentNetworkInfo(ctx, &proto.GetAgentNetworkInfoRequest{})
	if err != nil {
		return nil, err
	}
	if info.GetState() != proto.GetAgentNetworkInfoResponse_OK {
		return nil, fmt.Errorf("agent networks are not available: %s", strings.ToLower(info.GetState().String()))
	}
	if info.GetEndpoint() == "" {
		return nil, errors.New("management reported no Agent Networks endpoint")
	}
	return info, nil
}

func (s *AgentNetwork) renderHarness(ctx context.Context, req HarnessSetup) (*harness.Definition, []harness.Setting, harness.Env, error) {
	def, err := harness.Lookup(req.Harness)
	if err != nil {
		return nil, nil, harness.Env{}, err
	}
	info, err := s.setupInfo(ctx)
	if err != nil {
		return nil, nil, harness.Env{}, err
	}
	i := slices.IndexFunc(info.GetProviders(), func(p *proto.AgentNetworkProvider) bool { return p.GetId() == req.Provider })
	if i < 0 {
		return nil, nil, harness.Env{}, fmt.Errorf("provider %q is not available to this peer", req.Provider)
	}
	p := info.GetProviders()[i]
	v, ok := def.Variant(p.GetCatalogId(), p.GetApiFlavor())
	if !ok {
		return nil, nil, harness.Env{}, fmt.Errorf("%s cannot use provider %q", def.Name, p.GetName())
	}
	if req.Model != "" && !p.GetAllModelsAllowed() && len(p.GetModels()) > 0 && !slices.Contains(p.GetModels(), req.Model) {
		return nil, nil, harness.Env{}, fmt.Errorf("model %q is not allowed on %s", req.Model, p.GetName())
	}
	env, err := s.harnessEnv()
	if err != nil {
		return nil, nil, harness.Env{}, err
	}
	settings, err := def.Render(v, map[harness.Var]string{
		harness.VarEndpoint:      strings.TrimRight(info.GetEndpoint(), "/"),
		harness.VarModel:         req.Model,
		harness.VarVertexProject: strings.TrimSpace(req.VertexProject),
	}, env)
	if err != nil {
		return nil, nil, harness.Env{}, err
	}
	return def, settings, env, nil
}

func harnessProviders(def *harness.Definition, providers []*proto.AgentNetworkProvider) []HarnessProvider {
	out := []HarnessProvider{}
	for _, p := range providers {
		v, ok := def.Variant(p.GetCatalogId(), p.GetApiFlavor())
		if !ok {
			continue
		}
		hp := HarnessProvider{
			ID:                 p.GetId(),
			Name:               p.GetName(),
			Models:             append([]string{}, p.GetModels()...),
			AllModelsAllowed:   p.GetAllModelsAllowed(),
			DefaultModel:       v.DefaultModel,
			NeedsVertexProject: v.Uses(harness.VarVertexProject),
		}
		if len(hp.Models) > 0 {
			hp.DefaultModel = hp.Models[0]
		}
		out = append(out, hp)
	}
	return out
}

func harnessStatus(engine string) string {
	switch engine {
	case "configured":
		return harnessConfigured
	case "not configured":
		return harnessNotConfigured
	default:
		return harnessEdited
	}
}

func planFromEngine(plan *harness.Plan) HarnessPlan {
	out := HarnessPlan{
		Changes:  make([]HarnessChange, 0, len(plan.Changes)),
		Pending:  plan.Pending(),
		Snippets: []HarnessSnippet{},
		Backups:  []string{},
	}
	for _, c := range plan.Changes {
		out.Changes = append(out.Changes, HarnessChange{
			File:     c.File,
			Key:      harness.PathString(c.Path),
			Action:   string(c.Action),
			Before:   string(c.Before),
			After:    string(c.After),
			Conflict: c.Conflict,
		})
	}
	return out
}

func snippetPlan(file string, settings []harness.Setting) (HarnessPlan, error) {
	frags, err := harness.Fragments(settings)
	if err != nil {
		return HarnessPlan{}, err
	}
	out := HarnessPlan{Changes: []HarnessChange{}, Unparseable: file, Backups: []string{}}
	for _, f := range harness.SortedFiles(frags) {
		out.Snippets = append(out.Snippets, HarnessSnippet{File: f, Content: frags[f]})
	}
	return out, nil
}
