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
    public static readonly IReadOnlyList<string> Paradigms = ["rbac", "abac", "claims", "acl"];

    public static string Resolve(string? selector) =>
        selector is not null && Paradigms.Contains(selector) ? selector : Default;

    public static AuthzDecision Decide(string paradigm, AuthzRequest req, AuthzConfig cfg) => paradigm switch
    {
        "rbac" => RbacEvaluator.Evaluate(req.Caller, req.Action, req.Resource, cfg.Rbac),
        "abac" => AbacEvaluator.Evaluate(req.Caller, req.Action, req.Resource, cfg.Abac),
        "claims" => ClaimsEvaluator.Evaluate(req.Caller, req.Action, req.Resource),
        "acl" => AclEvaluator.Evaluate(req.Caller, req.Action, req.Resource, cfg.Acl),
        _ => new(false, $"unknown paradigm '{paradigm}'", paradigm),
    };
}
