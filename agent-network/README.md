# NetBird Agent Network

Agent Network is NetBird's access control layer for AI agents and the people who run them. 
It gives every agent a real identity, tied to an identity provider (IdP), and governs what it can reach: LLM APIs and 
AI gateways it can call, and the internal resources it can access. Traffic flows only over the encrypted NetBird tunnel, 
scoped by policy, with no API keys or other credentials to leak.

It also gives you control over cost. Because every LLM request passes through an
identity-aware proxy, you can:

- **Set spending and rate limits** per agent, per user, or per team — with hard caps
  that stop requests once a budget is reached.
- **Restrict models and providers** so agents can only call approved (and cost-appropriate)
  endpoints, keeping expensive models off-limits unless explicitly allowed.
- **Attribute usage** by tracking token consumption and cost per identity, so every
  request is tied back to the agent and person responsible.


https://github.com/user-attachments/assets/f76d549f-6ea8-45a2-b069-380037aff36a


> **Beta.** Agent Network is open source and can be self-hosted on your own
> infrastructure.

## How it works

Agent Network is built on two existing NetBird capabilities:

- **Overlay network** — the encrypted WireGuard mesh between peers.
- **Reverse proxy** — a NetBird peer that terminates LLM requests, establishes the
  caller's identity, evaluates policies/limits/guardrails, injects the upstream provider
  key server-side, forwards to the API or gateway, and records usage.

LLM traffic is routed through the proxy's identity-aware pipeline, while internal
resources (databases, internal APIs, self-hosted models) are reached directly over
peer-to-peer WireGuard tunnels, governed by the same identities and access policies.

## Where the code lives

There is no separate "agent-network" service — it reuses the reverse-proxy and management
components:

- [`proxy/`](../proxy) — the NetBird reverse proxy that serves the agent network endpoint
  and runs the per-request middleware pipeline.
- [`management/internals/modules/reverseproxy/`](../management/internals/modules/reverseproxy)
  — the management-side control plane: providers, policies, guardrails, limits, routing,
  and usage/access logs.

## Documentation

Full documentation, architecture, and quickstart:
**https://docs.netbird.io/agent-network**
