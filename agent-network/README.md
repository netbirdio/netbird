# NetBird Agent Network

Agent Network is NetBird's access control layer for AI agents and the people who run them. 
It gives every agent a real identity, tied to an identity provider (IdP), and governs what it can reach: LLM APIs and 
AI gateways it can call, and the internal resources it can access. Traffic flows only over the encrypted NetBird tunnel, 
scoped by policy, with no API keys or other credentials to leak. It also gives you control over cost and token usage.

Because every LLM request passes through an
identity-aware proxy, you can:

- **Set spending and rate limits** per agent, per user, or per team — with hard caps
  that stop requests once a budget is reached.
- **Restrict models and providers** so agents can only call approved (and cost-appropriate)
  endpoints, keeping expensive models off-limits unless explicitly allowed.
- **Attribute usage** by tracking token consumption and cost per identity, group, or cost center so every
  request is tied back to the agent and person responsible.
- **Reuse your existing AI gateway** — point the proxy at a gateway you already run,
  keeping its routing and config in place while it adds identity on top, so you skip
  API key distribution.

https://github.com/user-attachments/assets/44d18286-d8ab-49f8-a457-98ccd66f3268

> **Beta.** Agent Network is in beta, but it's stable and already running in
> production environments. It's fully open source and can be self-hosted on your own
> infrastructure, with no vendor lock-in and no data leaving your environment.

## How it works

Say you have a simple use case: your Engineering or IT team needs access to Claude Code or Codex, and you want visibility into usage plus the ability to enforce budgets.
How can you do that without creating a dedicated API key for every team?

With Agent Network you get a private endpoint inside your network, for example: https://mirror.netbird.ai
Teams configure their agents to point to that endpoint instead of using individual API keys directly. 

This endpoint is only reachable when users are connected to your NetBird network and authenticated through your IdP. Otherwise, it is not accessible from the public internet.
You can then use this private endpoint to configure your AI agents, whether that is Claude Code, Codex, or another tool.

## Quickstart

Full step-by-step setup:
**https://docs.netbird.io/agent-network/quickstart**

## Client settings that don't follow the endpoint

Most of an agent's traffic follows the base URL you hand it, but a few
client-side checks call their vendor directly and never reach the proxy. On a
network that blocks direct egress they fail even though inference works, so
they are worth setting once when you roll the endpoint out.

For Claude Code:

- **Fast mode** checks availability against `api.anthropic.com` rather than the
  configured base URL. Set `CLAUDE_CODE_SKIP_FAST_MODE_ORG_CHECK=1` when the
  agent authenticates with `ANTHROPIC_AUTH_TOKEN` alone (the usual shape when
  the proxy injects the real provider key) or when a TLS-inspecting proxy
  answers the check itself. Set
  `CLAUDE_CODE_SKIP_FAST_MODE_NETWORK_ERRORS=1` when the network refuses the
  connection outright. Fast mode is an Anthropic-API feature, so it is
  unavailable on a Bedrock- or Vertex-backed endpoint whatever you set.
- **Model discovery** is off by default. Set
  `CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1` for the picker to list the
  models your policies authorise; the proxy filters the response to that set.
  The client gives discovery a three-second budget and treats any redirect as
  a failure, so the endpoint must serve `/v1/models` directly.
- **The WebFetch domain safety check** also calls `api.anthropic.com` directly
  and is unaffected by the variables above.

Allowing direct egress to `api.anthropic.com` covers the network cases but not
the credential one, where the check reaches Anthropic and is rejected because
the agent presents a proxy-issued key.

## Architecture 

Agent Network is built on two existing NetBird capabilities:

- **Overlay network** — the encrypted WireGuard mesh between peers.
- **Reverse proxy** — a NetBird peer that terminates LLM requests, establishes the
  caller's identity, evaluates policies/limits/guardrails, injects the upstream provider
  key server-side, forwards to the API or gateway, and records usage.

LLM traffic is routed through the proxy's identity-aware pipeline, while internal
resources (databases, internal APIs, self-hosted models) are reached directly over
peer-to-peer WireGuard tunnels, governed by the same identities and access policies.

<img width="4720" height="2218" alt="image" src="https://github.com/user-attachments/assets/1afa5da1-4b82-4f8a-a7a8-f417efadf1eb" />


## Where the code lives

There is no separate "agent-network" service — it reuses the reverse-proxy and management
components:

- [`proxy/`](../proxy) — the NetBird reverse proxy that serves the agent network endpoint
  and runs the per-request middleware pipeline.
- [`management/internals/modules/reverseproxy/`](../management/internals/modules/reverseproxy)
  — the management-side control plane: providers, policies, guardrails, limits, routing,
  and usage/access logs.

## Access roles

Agent Network permissions build on the account permission matrix
([`management/server/permissions/`](../management/server/permissions)). The
`agent_network` area is split into dotted submodules (`agent_network.providers`,
`.policies`, `.guardrails`, `.budgets`, `.usage`, `.logs`, `.settings`); a role may
grant a single submodule or the parent, which cascades to all of them.

Two roles delegate Agent Network access without account-admin rights:

- **`agent_network_admin`** — full control over the whole `agent_network` area plus
  read-only users, groups, peers, and account info (needed to build policies).
  Nothing else in the account.
- **`usage_viewer`** — the regular User baseline plus read on
  `agent_network.usage` (the aggregated usage and cost overview) and read-only
  access to the resources the usage filters resolve against: users, groups,
  peers, and the provider list (connection config redacted — no upstream URLs
  or operator-supplied header values). No policies, and no account-wide
  request-level access logs; like any caller, it still reads its own requests
  through the self-scoped endpoints below.

Every authenticated user, regardless of role, can read the caller-scoped
self-service endpoint `GET /api/agent-network/agent-config` (the endpoint, providers,
and models the caller's own policies allow — what a local AI tool needs and nothing
more). The regular usage and access-log endpoints self-scope instead of denying:
a caller without the account-wide grant gets their own rows back, so "my usage"
and "my requests" are the same endpoints the admin dashboard uses. The provider
list self-scopes the same way — a caller without the providers grant gets the
providers their own policies authorize, reduced to the display surface, with
each provider's model list cut to what the caller's policy guardrails and the
provider's declared models effectively permit (the same computation the setup
answer and the proxy use). This feeds the dashboard's provider and model
filters. Role
definitions live in
[`management/server/permissions/roles/`](../management/server/permissions/roles).

## Documentation

Full documentation, architecture, and quickstart:
**https://docs.netbird.io/agent-network**
