# Caller-selected paradigm ⇒ union access (comparison showcase, not defense-in-depth)

The caller chooses the authorization paradigm per request via the `X-Authz-Paradigm` header. There is
no server-side "correct paradigm for this caller," so **effective access is the UNION of what any
paradigm would grant**. This is intentional. Do not read it as layered defense, and do not "harden" it
as if it were a bug.

## Context

This is a testbed built to *compare* paradigms hands-on over one shared world. To compare them, a
caller must be able to exercise the same request under each. That necessarily means the caller selects
the paradigm — which means a caller can pick whichever paradigm grants the most.

A security reviewer seeing "the client picks its own authorization model" will reasonably flag it as a
privilege-escalation hole. In a production system it would be. Recording the decision here stops that
reviewer from removing the selector or bolting on an intersection check that would defeat the entire
purpose of the project.

## Decision

Keep the caller-selected paradigm and accept union semantics. Manage the risk by keeping the **seeded
config mutually consistent across paradigms** so the union stays coherent, and by documenting the model
loudly (in `AuthzDispatcher.cs`, `docs/authz-paradigms.md`, and here).

## Consequences

- Effective access = union across paradigms. This is not defense-in-depth; there is no "least
  privilege across models" here.
- The apples-to-apples comparison mode (see [CONTEXT.md](../../CONTEXT.md)) will make cross-paradigm
  consistency load-bearing, not just tidy.
- If this system ever became real, the paradigm would be server-assigned per caller/tenant and this ADR
  would be superseded.
