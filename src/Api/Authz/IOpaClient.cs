namespace Api.Authz;

public interface IOpaClient
{
    // POSTs {"input": input} to the decision rule and returns decision.permit.
    Task<bool> DecideAsync(object input, CancellationToken ct);
}
