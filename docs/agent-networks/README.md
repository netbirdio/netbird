# Agent Networks — architecture documentation

A self-contained set of documents describing the agent-networks feature:
an LLM-aware reverse-proxy middleware system plus account-level controls
(budget rules, log collection toggles, PII redaction). The management
server synthesises a per-peer middleware chain that the proxy executes on
every LLM request.

## What to read first

1. **[00-overview.md](00-overview.md)** — the single entry point. Feature
   scope, the module map, and the cross-cutting topics worth keeping in
   mind, with links to every per-module guide.
2. **[01-end-to-end-flows.md](01-end-to-end-flows.md)** — three
   high-level mermaid diagrams: config-to-runtime synth/delivery,
   per-request lifecycle through the LLM chain, and the budget-rule
   feedback loop.
3. **Per-module guides** under `modules/` — one file per package. Each
   describes the module boundary, the file-level layout, its own flow
   diagrams, the public contracts, the invariants it relies on, and the
   areas worth the closest attention.

## Directory layout

```
docs/agent-networks/
├── README.md                              # you are here
├── 00-overview.md                         # feature summary + module map
├── 01-end-to-end-flows.md                 # cross-module mermaid diagrams
└── modules/
    ├── 10-shared-api.md                   # proto + OpenAPI wire contracts
    ├── 20-management-store.md             # SQL persistence layer
    ├── 21-management-agentnetwork.md      # domain layer + synthesizer (largest)
    ├── 22-management-handlers-wiring.md   # HTTP API + gRPC delivery
    ├── 30-proxy-middleware-framework.md   # generic plugin system
    ├── 31-proxy-middleware-builtin.md     # 8 LLM-aware middlewares
    ├── 32-proxy-llm-parsers.md            # OpenAI/Anthropic/Bedrock SDKs + pricing
    ├── 33-proxy-runtime.md                # translate + serve + access-log
    ├── 40-dashboard.md                    # UI for everything above (lives in the dashboard repo)
    └── 50-path-routed-providers.md        # Vertex AI + Bedrock (path-routed, keyfile:: creds, /bedrock prefix)
```

The `40-dashboard.md` module documents code that lives in the **dashboard
repo**, not in this repo. The guide is co-located here so backend readers
see the full picture in one place.

## How the per-module guides are structured

Every `modules/*.md` follows the same template so the docs are easy to
scan:

- **Module boundary** — what this package owns; where it sits in the stack.
- **Files** — path / role.
- **Architecture & flow** — one or more mermaid diagrams.
- **Public contracts** — function signatures, gRPC messages, JSON shapes.
- **Invariants** — semantic guarantees the module relies on or enforces.
- **Things to scrutinize** — split by correctness / security /
  concurrency / backward-compat / performance / observability.
- **Test coverage** — the test files that lock down behaviour in this
  module.
- **Known limitations / non-goals** — what is intentionally out of scope.
- **Cross-references** — upstream/downstream module links + the
  end-to-end flow + the overview.

See [00-overview.md](00-overview.md) for the module map and the
cross-cutting topics.
