using Api.Auth;
using Api.Authz;
using Api.Data;
using Api.Storage;
using FastEndpoints;

namespace Api.Endpoints;

public sealed record WriteRequest(string Key, string Content);

public sealed class StorageWriteEndpoint(AuthzConfigStore store, S3Gateway s3, AppDbContext db,
    IReadOnlyDictionary<string, IExternalEvaluator> external)
    : Endpoint<WriteRequest, StorageResult>
{
    public override void Configure()
    {
        Post("/storage/write");
        Policies("authenticated");
    }

    public override async Task HandleAsync(WriteRequest req, CancellationToken ct)
    {
        var caller = CallerClaims.FromPrincipal(User);
        var paradigm = AuthzDispatcher.Resolve(HttpContext.Request.Headers["X-Authz-Paradigm"].ToString());
        var ctx = new AuthzContext(
            HttpContext.Request.Headers["X-Break-Glass"].ToString().Equals("true", StringComparison.OrdinalIgnoreCase));
        var decision = await AuthzDispatcher.DecideAsync(paradigm, new AuthzRequest(caller, StorageAction.Write, req.Key, ctx), store.Current, external, ct);

        if (!decision.Permit)
        {
            await Send.ResponseAsync(new StorageResult(paradigm, false, decision.Reason, req.Key, null), 403, ct);
            return;
        }

        await s3.PutAsync(req.Key, req.Content, ct);
        db.AuditEntries.Add(new AuditEntry
        {
            At = DateTimeOffset.UtcNow,
            Subject = caller.Subject,
            RoleArn = paradigm,
            ObjectKey = req.Key,
        });
        await db.SaveChangesAsync(ct);

        await Send.OkAsync(new StorageResult(paradigm, true, decision.Reason, req.Key, req.Content), ct);
    }
}
