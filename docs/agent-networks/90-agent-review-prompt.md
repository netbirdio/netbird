# Prompt for an AI code reviewer

Self-contained prompt to feed to a second AI agent (Claude, GPT, etc.)
so it can perform structured code review of the agent-networks PR in
parallel with the human reviewers. Copy the **Prompt** block below into
the agent's first message. The agent should produce a single markdown
report at a path you specify.

The prompt assumes the agent has filesystem read access to the netbird
and dashboard repos and can run `git`, but does NOT have permission to
modify or commit anything.

---

## Prompt

```
You are reviewing a large PR pair for security, correctness, concurrency,
backward-compatibility, performance, and observability. You are read-only
on both repos: do NOT modify any file, do NOT commit anything, do NOT
stage anything, do NOT run e2e scripts. Only read code and emit a single
markdown report at:

  /Users/maycon/projects/claude-contexts/netbird/agent-networks-pr/AGENT_REVIEW_REPORT.md

REPOS
  Backend:   /Users/maycon/projects/netbird       (branch feature/agent-networks-backend, merge-base 14af17955)
  Dashboard: /Users/maycon/projects/dashboard     (branch feature/agent-networks, merge-base main)

PR CONTEXT
  Backend: 28 commits, ~28k LOC added across 150 files.
  Dashboard: ~70 commits, ~10k LOC added across 82 files.
  The PR introduces an LLM-aware reverse-proxy middleware system for
  NetBird agent-networks plus account-level controls (budget rules,
  PII redaction, log + prompt capture toggles). The management server
  synthesises a per-peer middleware chain that the proxy executes for
  every LLM request; the chain enforces quotas, injects identity,
  redacts PII, parses tokens / cost, and emits access-log entries.

REQUIRED INPUT — read these BEFORE reading any code

  /Users/maycon/projects/claude-contexts/netbird/agent-networks-pr/README.md
  /Users/maycon/projects/claude-contexts/netbird/agent-networks-pr/00-overview.md
  /Users/maycon/projects/claude-contexts/netbird/agent-networks-pr/01-end-to-end-flows.md

  AND the per-module guide for every module you intend to review:
    modules/10-shared-api.md
    modules/20-management-store.md
    modules/21-management-agentnetwork.md
    modules/22-management-handlers-wiring.md
    modules/30-proxy-middleware-framework.md
    modules/31-proxy-middleware-builtin.md
    modules/32-proxy-llm-parsers.md
    modules/33-proxy-runtime.md
    modules/40-dashboard.md

  Each guide names its reviewer profile, lists commits in scope, shows
  the file map, names invariants, and enumerates "Things to scrutinize".
  Use those lists to focus your reading — do not re-derive what the
  guides already documented.

YOUR JOB
  For each module, validate that the invariants in the guide actually
  hold in the code, and find anything the guide missed. The guide is
  your CHECKLIST, not the truth — it is itself a draft. Flag any place
  where the guide is wrong, stale, or misleading.

FOCUS AREAS (in priority order)
  1. Security
     - Privilege boundaries: account isolation in store queries; group
       resolution can never cross accounts.
     - PII handling: every metadata channel out of the proxy must
       respect redact_pii when enabled. Confirm at every JSON-marshal
       site, every access-log write, every gRPC outbound message.
     - Capture-pointer semantics (*bool for capture_prompt /
       capture_completion): nil = legacy emit, false = suppress,
       true = emit. Verify every json hop preserves nil vs false.
     - api_key fields on AgentNetworkProviderRequest must be
       write-only — never echoed on responses.
     - UpstreamRewrite.AuthHeader deliberately bypasses the header
       denylist. Confirm consumers only unpack it via the trusted
       upstream-build path; flag if any code path lets a synth-untrusted
       caller stage a fake AuthHeader.
     - Permission keys on every HTTP handler. Confirm permission?.services?.read
       gates every read; permission?.services?.write gates writes.

  2. Correctness
     - Min-wins all-must-pass budget rule semantics in
       management/agentnetwork: every matching rule's remaining quota
       must be > 0 for the request to proceed. Verify the
       check + record pair stays consistent (no orphan decrements,
       no double-count on retries).
     - llm_limit_check ↔ llm_limit_record pairing — a successful check
       must always result in a corresponding record (or the rate-limit
       counters skew). Look for early-returns / panics that could
       break the pair.
     - ProxyMapping.Private preservation on per-proxy live updates
       (263dabd73). Failure mode: auth skips ValidateTunnelPeer →
       CapturedData.UserGroups empty → llm_router denies. Verify the
       fix covers every gRPC translation path.
     - respInput carrying UserEmail/UserGroups/UserGroupNames onto
       the response leg (reverseproxy.go:196-223, b438a7194). If this
       wire breaks, llm_limit_record ships empty group_ids and
       budget decrements miss.
     - agent_network_chain_realstack_test.go inlines proto→Spec
       mapping instead of calling middleware_translate.go — confirm
       this drift risk, suggest fix.

  3. Concurrency
     - Chain replacement under in-flight requests in proxy/runtime.
       Confirm no goroutine sees a half-replaced chain.
     - Body-tap memory bounds: 1 MiB per-direction cap, 256 MiB shared
       Budget semaphore. Verify the Budget release path runs on every
       exit (including panic + timeout).
     - cloneInputFor deep-copies the body up to 16 times per chain.
       Note allocation cost; flag if benchmarks are missing.
     - InvalidateMiddleware + LiveServiceCheck race — flag if the
       guide says no test exists.

  4. Backward compatibility
     - All proto field numbers in proxy_service.proto are in unused
       slots; OpenAPI additions are appended; no existing schemas
       lose required-ness. Confirm by diffing 14af17955..HEAD on
       shared/management/proto/proxy_service.proto and
       shared/management/http/api/openapi.yml.
     - Pointer fields for capture flags preserve nil-default emission
       so existing proxies that don't know about the field keep
       working.
     - Non-agent-network services on the proxy must still work.
       Verify ServiceMapping doesn't gate on agent_network=true.

  5. Performance
     - SynthesizeServices runs on every NetworkMap push. With N
       connected peers × M policies × K providers, what's the worst
       case allocation? Flag any O(N²) loop hidden in the synthesiser.
     - cloneInputFor allocates per middleware invocation. Estimate
       p99 request-time overhead under a 16-middleware chain.
     - Streaming response handling — the SSE parser must not buffer
       the whole stream.

  6. Observability
     - Activity codes added for budget-rule decisions. Verify each
       has a UI label in the dashboard.
     - access-log fields (provider, model, tokens, cost, deny_code,
       agent_network flag) match what the dashboard renders.
     - Metrics surface: list every metric added in
       proxy/internal/metrics + proxy/internal/middleware/metrics.

  7. Tests
     - For every "what to scrutinize" bullet, find the test that
       locks it down. If none exists, flag as a coverage gap.
     - Real-store coverage in management/agentnetwork (no mocks)
       is a stated goal — confirm and list any remaining mocks.
     - Bodytap truncation-replay test missing; Dispatcher
       timeout/panic tests missing; concurrent Budget exhaustion test
       missing — confirm these gaps from
       modules/30-proxy-middleware-framework.md.

OUT OF SCOPE — do not flag these as issues
  - Reaper / GC pass over stale synth services (scope-cut per AN-0)
  - URL-sync for tab state on AI Observability page
  - npm run lint broken on dashboard (pre-existing Next 16 issue)
  - Style nitpicks unless they affect correctness
  - Anything in MEMORY.md or claude-contexts/ paths

OUTPUT FORMAT (single markdown file)

# Agent review — agent-networks PR

## Summary
- Modules reviewed: <list>
- Findings: <N total — H high, M medium, L low>
- Most concerning: <one-line>
- Disagreements with the human review guides: <list or "none">

## Findings
For each finding:
### F<n>. <Short title> — <severity H/M/L> — module <ID>
  - **Where:** file:line (or file:line-range)
  - **What:** one sentence on the problem
  - **Why it matters:** consequence in production
  - **Evidence:** code snippet (≤20 lines) + reasoning
  - **Suggested fix:** one paragraph
  - **Test that would catch it:** suggest a test name + the assertion shape

## Gaps in the human review guides
For every place the guide is wrong, stale, missing, or misleading:
  - **Guide:** modules/<file>.md section
  - **Issue:** <what the guide says vs reality>
  - **Suggested edit:** <one sentence>

## Confirmations
List the high-stakes invariants you VERIFIED:
  - <invariant> — confirmed at file:line

## Methodology
- Files actually read: <N>
- Commits examined individually (git show): <list of SHAs>
- Anything you didn't review and why: <list>

CONSTRAINTS
  - Read-only. Do not modify ANY file in either repo.
  - Statically-analyzable bash only — no $(), pipes, &&, or grep in
    Bash commands. Use Read for file content.
  - Use absolute paths (no cd).
  - Cite file:line for every concrete claim.
  - Severity rubric:
      H — could cause data loss, security boundary breach, runaway spend,
          or service outage in prod with realistic inputs.
      M — correctness bug under non-rare conditions, missing security
          control with a defense-in-depth replacement, or a perf issue
          that surfaces under typical load.
      L — code-smell, missing test, doc drift, minor inefficiency.
  - When in doubt about severity, write your reasoning; do not inflate.
  - The whole report must fit under 8000 words. If your draft is longer,
    cut the LOWEST-severity findings first.

When done, reply with a one-line confirmation including the absolute
report path and the finding counts (H/M/L).
```

---

## How to use this prompt

1. Spawn a second AI session (Claude Code, web Claude, or another agent
   with tool access). Make sure it can read both repos and write to
   `~/projects/claude-contexts/`.
2. Paste the **Prompt** block above as the agent's first message.
3. When the agent finishes, the report lands at
   `~/projects/claude-contexts/netbird/agent-networks-pr/AGENT_REVIEW_REPORT.md`.
4. Diff the agent's findings against your own / your team's review notes
   — disagreements are often the most useful signal.
5. Iterate: if the agent missed something, refine this prompt and re-run.

## Notes for the human running the prompt

- The prompt is intentionally bossy about scope and severity. Soft
  prompts produce padded reports.
- The "Out of scope" list is the most-edited part: keep it in sync
  with what your team has agreed NOT to fix in this PR.
- If you want a more shallow second-opinion run, drop the OUTPUT FORMAT
  section and ask for "your top 10 concerns in plain prose."
- If you want a deeper run, add a second pass that asks the agent to
  rate every claim in the human review guides as `correct` / `wrong` /
  `unclear` with citations.
