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

## Documentation

Full documentation, architecture, and quickstart:
**https://docs.netbird.io/agent-network**
