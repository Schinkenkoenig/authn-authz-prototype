namespace Api.Authz;

// The in-memory config bundle the store loads once at startup (claim-based needs none — it reads
// the token).
public sealed record AuthzConfig(RbacConfig Rbac, AbacConfig Abac, AclConfig Acl);

// The thin data seam: pick an evaluator by selector, route the request. No engine hierarchy.
//
// SECURITY MODEL: the caller chooses the paradigm per request (X-Authz-Paradigm). There is no
// server-side "correct paradigm for this caller", so effective access is the UNION of what any
// paradigm would grant — this is a comparison showcase, NOT layered defense. Keep the seeded
// config across paradigms mutually consistent, and do not read this as defense-in-depth.
public static class AuthzDispatcher
{
    public const string Default = "rbac";
    public static readonly IReadOnlyList<string> Paradigms = ["rbac", "abac", "claims", "acl", "rebac"];

    public static string Resolve(string? selector) =>
        selector is not null && Paradigms.Contains(selector) ? selector : Default;

    // The four in-process paradigms: pure, synchronous, config-driven.
    public static AuthzDecision Decide(string paradigm, AuthzRequest req, AuthzConfig cfg) => paradigm switch
    {
        "rbac" => RbacEvaluator.Evaluate(req.Caller, req.Action, req.Resource, cfg.Rbac),
        "abac" => AbacEvaluator.Evaluate(req.Caller, req.Action, req.Resource, cfg.Abac),
        "claims" => ClaimsEvaluator.Evaluate(req.Caller, req.Action, req.Resource),
        "acl" => AclEvaluator.Evaluate(req.Caller, req.Action, req.Resource, cfg.Acl),
        _ => new(false, $"unknown paradigm '{paradigm}'", paradigm),
    };

    // The async variant of the seam. ReBAC's graph lives in OpenFGA, so its decision is an awaited
    // network Check — it can't be a pure (claims,action,resource,config) function. The four sync
    // paradigms delegate to Decide; only rebac awaits. rebac needs the injected client, so it denies
    // when the client is absent (e.g. OpenFGA not configured).
    public static Task<AuthzDecision> DecideAsync(
        string paradigm, AuthzRequest req, AuthzConfig cfg, IRebacClient? rebac, CancellationToken ct) =>
        paradigm switch
        {
            "rebac" => rebac is null
                ? Task.FromResult(new AuthzDecision(false, "ReBAC engine not configured", "rebac"))
                : RebacEvaluator.EvaluateAsync(req.Caller, req.Action, req.Resource, rebac, ct),
            _ => Task.FromResult(Decide(paradigm, req, cfg)),
        };
}
