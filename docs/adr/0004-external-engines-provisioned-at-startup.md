# External engines behind IExternalEvaluator, provisioned at startup

The three engine-backed paradigms (`rebac` → OpenFGA, `cedar` → cedar-agent, `opa` → OPA) each
implement `IExternalEvaluator { Paradigm; EvaluateAsync }`, are resolved from a paradigm→evaluator
dictionary, and have their model/policy **provisioned into the engine at API startup**, fail-fast.

## Context

An external engine decides over a network call, so it cannot be a pure `(caller, action, resource,
config)` function like the in-process paradigms ([ADR 0003](0003-pluggable-pdp-thin-data-seam.md)). The
seam had to grow an async path without dragging `async` into the pure evaluators. The engines also
start empty (in-memory OpenFGA, unloaded cedar-agent/OPA) — their authorization data has to get *in*
somehow, and drift between the app's expected model and the engine's loaded model must be caught early.

## Decision

- `AuthzDispatcher.DecideAsync` looks the paradigm up in an injected `IExternalEvaluator` dictionary;
  everything not in the map delegates to the pure synchronous `Decide`. The four in-process evaluators
  stay pure (they wrap their result in `Task.FromResult`).
- Each engine's model/policy is pushed at startup by a provisioner (`RebacProvisioner`,
  `CedarProvisioner`, `OpaProvisioner`), the same shape as the DB `migrate → seed → load`. If a
  configured engine is unreachable, startup **fails fast** rather than limping.
- A paradigm whose engine URL is unset gets an `UnconfiguredEvaluator` that **denies** — so the other
  paradigms keep working when one engine is absent, and an unconfigured engine can never accidentally
  permit.

## Consequences

- The engines are in-memory, so they lose their provisioned data on container recreate; the startup
  provisioner re-pushes it, which is why an engine can be wiped and the API restarted freely.
- A model/policy edit is only picked up on a re-provision — i.e. restart the API (and, for a reused
  OpenFGA store, recreate the container). Same no-hot-reload shape as the Keycloak realm.
- Every engine payload shape is proven with `curl` against the live container before any C# is written
  (see AGENTS.md) — provisioning-at-startup makes that the natural first step.
