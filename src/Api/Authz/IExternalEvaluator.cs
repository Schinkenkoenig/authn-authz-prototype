namespace Api.Authz;

// An authorization paradigm whose decision requires awaited I/O to an external engine (OpenFGA,
// cedar-agent, OPA). Registered once per engine; DecideAsync dispatches by Paradigm. The four
// in-process paradigms stay pure/sync in AuthzDispatcher.Decide and do NOT implement this.
public interface IExternalEvaluator
{
    string Paradigm { get; }
    Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct);
}

// Stand-in for an external engine whose URL is unset: selecting that paradigm denies rather than
// throwing, so the other paradigms keep working without the engine.
public sealed class UnconfiguredEvaluator(string paradigm) : IExternalEvaluator
{
    public string Paradigm => paradigm;
    public Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct) =>
        Task.FromResult(new AuthzDecision(false, $"{paradigm} engine not configured", paradigm));
}
