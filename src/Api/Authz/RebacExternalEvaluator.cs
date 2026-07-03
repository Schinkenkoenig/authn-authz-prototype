using Api.Auth;

namespace Api.Authz;

// Adapts the existing ReBAC pieces (pure RebacEvaluator mapping + IRebacClient OpenFGA Check) to
// the IExternalEvaluator seam. Behavior is unchanged from SP3.
public sealed class RebacExternalEvaluator(IRebacClient client) : IExternalEvaluator
{
    public string Paradigm => "rebac";
    public Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct) =>
        RebacEvaluator.EvaluateAsync(req.Caller, req.Action, req.Resource, client, ct);
}
