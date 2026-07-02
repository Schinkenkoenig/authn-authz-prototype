using Api.Auth;
using Api.Authz;
using Api.Data;
using Api.Storage;
using FastEndpoints;

namespace Api.Endpoints;

public sealed record RoundtripResult(
    string Subject,
    string Name,
    IReadOnlyList<string> Roles,
    string RoleArn,
    string ObjectKey,
    bool ContentMatched);

// The money path: validate the access token (done by the auth layer), resolve the
// caller's role + prefix (PDP), broker prefix-scoped temp creds via STS, then PUT and
// GET back an object under the caller's own prefix. Ceph RGW is the PEP that enforces it.
public sealed class StorageRoundtripEndpoint(
    CephSettings ceph, StsBroker sts, S3Gateway s3, AppDbContext db)
    : EndpointWithoutRequest<RoundtripResult>
{
    public override void Configure()
    {
        Post("/storage/roundtrip");
        Policies("authenticated");
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var caller = CallerClaims.FromPrincipal(User);

        // The ID token (aud=webapp) is what STS federates on — forwarded by the SPA,
        // distinct from the access token (aud=api) that authorized this call.
        var idToken = HttpContext.Request.Headers["X-Id-Token"].ToString();
        if (string.IsNullOrEmpty(idToken))
        {
            await Send.ResponseAsync(new RoundtripResult(caller.Subject, caller.Name, caller.Roles, "", "", false), 400, ct);
            return;
        }

        var prefix = $"{caller.Name}/";
        var roleArn = RoleResolver.ResolveRoleArn(caller.Roles);
        var sessionPolicy = SessionPolicy.ForPrefix(ceph.Bucket, prefix);

        var creds = await sts.AssumeAsync(roleArn, caller.Subject, idToken, sessionPolicy, ct);

        var key = $"{prefix}roundtrip-{Guid.NewGuid():N}.txt";
        var content = $"walking-skeleton {DateTimeOffset.UtcNow:O}";
        await s3.PutAsync(creds, key, content, ct);
        var readBack = await s3.GetAsync(creds, key, ct);

        db.AuditEntries.Add(new AuditEntry
        {
            At = DateTimeOffset.UtcNow,
            Subject = caller.Subject,
            RoleArn = roleArn,
            ObjectKey = key,
        });
        await db.SaveChangesAsync(ct);

        await Send.OkAsync(
            new RoundtripResult(caller.Subject, caller.Name, caller.Roles, roleArn, key, readBack == content),
            ct);
    }
}
