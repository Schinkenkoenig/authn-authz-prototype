# Prefix is an arbitrary namespace, decoupled from caller identity

A resource's prefix is an arbitrary namespace (`projects/`, `finance/`, `hr/`) with **no built-in
relationship to the caller's identity**. Authorization is decided by a configured paradigm, never by a
structural `prefix == username` rule.

## Context

The walking skeleton (SP1) coupled the two: every object key lived under the caller's own `name/`
prefix, and cross-user access was impossible *by construction* — the prefix was the caller's username.
That is genuinely safe, and it is the "obvious" default a future reader might try to reinstate. But it
makes authorization structural and trivial, which defeats the entire purpose of the project: you cannot
compare seven authorization paradigms if the answer is always "the prefix is you."

## Decision

Decouple prefix from identity (SP2). Prefixes are arbitrary shared namespaces; who may do what to them
is decided by the selected paradigm's configuration ([ADR 0003](0003-pluggable-pdp-thin-data-seam.md)),
not by whether the prefix matches the caller's name. This reverses the SP1 coupling deliberately.

## Consequences

- Cross-user access is now a *policy* question, not a structural impossibility — which is the point:
  it gives every paradigm something real to decide over one shared world.
- The safety-by-construction guarantee of SP1 is gone. That safety net is replaced by the API's own
  enforcement ([ADR 0001](0001-service-iam-app-level-authz.md)) plus deliberately-consistent seeded
  config ([ADR 0005](0005-caller-selected-paradigm-union-access.md)).
- Do not reintroduce a `prefix == username` shortcut as a "fix." It would look like a hardening
  improvement and would quietly collapse the comparison the whole system exists to demonstrate.
