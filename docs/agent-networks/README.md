# agent-networks PR — review pack

A self-contained set of review documents for the agent-networks PR pair:
`feature/agent-networks-backend` on this repo (netbird) and
`feature/agent-networks` on the dashboard repo.

## What to read first

1. **[00-overview.md](00-overview.md)** — the single entry point. PR
   scope, commit list, ownership matrix, risk hot-list, and links to
   every per-module guide.
2. **[01-end-to-end-flows.md](01-end-to-end-flows.md)** — three
   high-level mermaid diagrams: config-to-runtime synth/delivery,
   per-request lifecycle through the LLM chain, and the budget-rule
   feedback loop.
3. **Per-module guides** under `modules/` — one file per
   review-able package. Each names its reviewer profile, lists commits
   in scope, shows file-level changes, includes its own flow diagrams,
   and calls out what to scrutinize.
4. **[90-agent-review-prompt.md](90-agent-review-prompt.md)** — a
   self-contained prompt to feed to another AI agent (or a parallel
   reviewer) to perform structured code review against the same scope.

## Directory layout

```
docs/agent-networks/
├── README.md                              # you are here
├── 00-overview.md                         # PR summary + ownership matrix
├── 01-end-to-end-flows.md                 # cross-module mermaid diagrams
├── 90-agent-review-prompt.md              # prompt for an AI code reviewer
└── modules/
    ├── 10-shared-api.md                   # proto + OpenAPI wire contracts
    ├── 20-management-store.md             # SQL persistence layer
    ├── 21-management-agentnetwork.md      # domain layer + synthesizer (largest)
    ├── 22-management-handlers-wiring.md   # HTTP API + gRPC delivery
    ├── 30-proxy-middleware-framework.md   # generic plugin system
    ├── 31-proxy-middleware-builtin.md     # 8 LLM-aware middlewares
    ├── 32-proxy-llm-parsers.md            # OpenAI/Anthropic/Bedrock SDKs + pricing
    ├── 33-proxy-runtime.md                # translate + serve + access-log
    ├── 40-dashboard.md                    # UI for everything above (lives in the dashboard repo at feature/agent-networks)
    └── 50-path-routed-providers.md        # Vertex AI + Bedrock (path-routed, keyfile:: creds, /bedrock prefix)
```

The `40-dashboard.md` module documents code that lives in the **dashboard
repo** (`feature/agent-networks` branch), not in this repo. The guide is
co-located here so backend reviewers see the full picture in one place.

## How the per-module guides are structured

Every `modules/*.md` follows the same template so reviewers can scan a
familiar shape:

- **Reviewer profile / time / risk / backward-compat impact** — fits in
  a single quote block at the top so triaging the file is a one-glance
  decision.
- **Module boundary** — what this package owns within the PR; where it
  sits in the stack.
- **Commits in scope** — pinned to the file scope, not the whole PR.
- **Files changed** — path / status / LOC / role.
- **Architecture & flow** — one or more mermaid diagrams.
- **Public contracts** — function signatures, gRPC messages, JSON
  shapes, etc.
- **Invariants** — semantic guarantees the module relies on or
  enforces.
- **Things to scrutinize** — split by correctness / security /
  concurrency / backward-compat / performance / observability.
- **Test coverage** — every test file that locks down behavior in this
  module.
- **Known limitations / non-goals** — what reviewers should NOT flag as
  bugs (out of scope on purpose).
- **Cross-references** — upstream/downstream module links + the
  end-to-end flow + the overview.

## Repos covered

- **Backend (this repo):** `feature/agent-networks-backend` —
  28 commits vs merge-base `14af17955`, ~28k net LOC added.
- **Dashboard:** `feature/agent-networks` on
  `netbirdio/netbird-dashboard` — ~70 commits vs `main`, ~10k net LOC
  added.

See [00-overview.md](00-overview.md) for the full ownership matrix,
commit roll-up, and cross-cutting risk hot-list.
