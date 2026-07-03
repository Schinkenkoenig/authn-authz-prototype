namespace Api.Authz;

// A thin seam over OpenFGA's Check API: the store id and authorization model id are baked into the
// implementation at startup, so the evaluator only supplies (user, relation, object). Injected into
// the storage endpoints; awaited by RebacEvaluator.
public interface IRebacClient
{
    Task<bool> CheckAsync(string user, string relation, string obj, CancellationToken ct);
}
