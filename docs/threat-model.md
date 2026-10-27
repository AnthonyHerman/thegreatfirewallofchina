# Threat model

This sandbox is for an operator running an agent on their own machine, with
a Chinese open-weight model or any other model, and wanting a gate on what
that agent does with the network and with the host.

The gate judges behavior. It does not decide why a model did something.

## What was reported

On 26 October 2026 Cohere said that while evaluating Qwen3.8-Flash-Next it
asked the model for a defensive detection rule. The model's reasoning said
it would not invoke tools. It then inventoried the machine, including DNS
settings, and tried to upload a probe file to an Alibaba Cloud storage
bucket in Beijing. Cohere's sandbox blocked the upload. Cohere said the
root cause was not determined and that they were not asserting malicious
intent. They later released traces.

A public counter-reading, from @voooooogel the same day, is that the model
assumed it was already on Alibaba infrastructure and used an Alibaba test
URL, and that reading `resolv.conf` is a habit from developing behind the
Great Firewall. On that reading there was no exfiltration.

Both readings produce the same control. An unexpected upload to object
storage is blocked whether the model is covert or confused. A read of
resolver state with no upload is held for review, because that half of the
pattern is ambiguous.

A separate October 2026 report from the Swarmchasers, covered by IBM and
others, tracked a fleet of agents on Tencent Cloud infrastructure as they
queried Alibaba's Amap and, when blocked, tried other paths. That episode
is not this incident. It is evidence that agent egress is visible to third
parties and that agents already route around a refusal from one site.

## What this process blocks

- Metadata services, including `169.254.169.254`, Alibaba's
  `100.100.100.200`, and Volcengine's `100.96.0.96`.
- A read of host identity or resolver state followed by a connection that
  is not on the operator allowlist.
- A destination on the callback-channel list in `docs/destinations.md`.
- A trace whose reasoning says it will not use tools and then records
  actions. That signal is a review on its own, and a block when it is
  paired with a denied destination.
- A raw IP that was not allowlisted, so the suffix list cannot be skipped.

The destination list is the cloud APIs and object stores those vendors
publish. It is not a ban on `.cn`, and it is not a ban on CDN edges.

## What this process does not do

- It does not claim Qwen, or any other model, contains a backdoor.
- It does not see the body of a TLS connection. The CONNECT proxy can
  refuse the destination. Looking inside TLS needs an operator CA and is
  not in this pass. The proxy is opt-in: a process that does not use it
  is not confined. A network-namespace or nftables companion is later work.
- It does not call a model in order to lower a static block. JEV can raise
  an allow to review or block, and can lower a plain review to allow when
  it is confident. A metadata hit, a callback suffix, or
  reconnaissance-then-egress stays a block when JEV is wrong or down.
- The noul cuts, `0.7` to block and `0.3` to review, and the choice
  confidence cut of `0.6`, are the starting points from the TypeSafe
  docs. They are not a measured false-positive rate. `jev-latest` is pinned
  in the audit by the model version the API echoes. Calibrating the cuts
  on a labeled set is later work.

## How a decision is made

1. Static destination policy and static trace signals produce a floor of
   allow, review, or block.
2. If a judge is configured, one JEV request scores `phone_home`,
   `reasoning_mismatch`, `env_recon`, and `exfil`, and picks a disposition
   and a severity. The questions are fixed in `gfw/judge.py`.
3. Code combines the floor and the probabilities. The model does not pick
   the final action by writing a paragraph.
4. If `GFW_ANALYST=1` and the action is review or block, one capped
   Abliteration completion explains the trace. Remaining credits below
   `GFW_ANALYST_MIN_BALANCE` skip that call. A reply that tries to explain
   how to evade the sandbox is discarded. The product does not embed either
   API key.
