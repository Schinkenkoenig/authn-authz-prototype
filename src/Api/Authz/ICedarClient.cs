namespace Api.Authz;

public interface ICedarClient
{
    // POSTs the is_authorized query; returns (allow, reason) where reason is the deciding policy id.
    Task<(bool Allow, string Reason)> IsAuthorizedAsync(
        string principal, string action, string resource, object context, CancellationToken ct);
}
