using Amazon.S3;
using Api.Auth;
using Api.Authz;
using Api.Storage;
using FastEndpoints;

namespace Api.Endpoints;

public sealed record ReadRequest(string Key);
public sealed record StorageResult(string Paradigm, bool Permit, string Reason, string Key, string? Content);

// Read is gated by the selected paradigm, then served with the service identity. The paradigm
// comes from the X-Authz-Paradigm header (default when absent/unknown).
public sealed class StorageReadEndpoint(AuthzConfigStore store, S3Gateway s3,
    IReadOnlyDictionary<string, IExternalEvaluator> external)
    : Endpoint<ReadRequest, StorageResult>
{
    public override void Configure()
    {
        Post("/storage/read");
        Policies("authenticated");
    }

    public override async Task HandleAsync(ReadRequest req, CancellationToken ct)
    {
        var caller = CallerClaims.FromPrincipal(User);
        var paradigm = AuthzDispatcher.Resolve(HttpContext.Request.Headers["X-Authz-Paradigm"].ToString());
        var decision = await AuthzDispatcher.DecideAsync(paradigm, new AuthzRequest(caller, StorageAction.Read, req.Key), store.Current, external, ct);

        if (!decision.Permit)
        {
            await Send.ResponseAsync(new StorageResult(paradigm, false, decision.Reason, req.Key, null), 403, ct);
            return;
        }

        string content;
        try { content = await s3.GetAsync(req.Key, ct); }
        catch (AmazonS3Exception ex) { content = $"(read failed: {ex.ErrorCode})"; }

        await Send.OkAsync(new StorageResult(paradigm, true, decision.Reason, req.Key, content), ct);
    }
}
