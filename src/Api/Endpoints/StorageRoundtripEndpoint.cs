using Amazon.S3;
using Api.Auth;
using Api.Authz;
using Api.Data;
using Api.Storage;
using FastEndpoints;

namespace Api.Endpoints;

public sealed record StorageDemoResult(
    string Subject,
    string Name,
    IReadOnlyList<string> Roles,
    string RoleArn,
    string Prefix,
    string ReadKey,
    string ReadContent,
    bool WriteAllowed,
    string WriteDetail,
    string? WriteKey);

// The money path AND the authz showcase. After brokering prefix-scoped temp creds via
// STS (ABAC), it exercises two capabilities so the RBAC layer is visible:
//   READ  — GET the seeded welcome object; succeeds for both reader and writer.
//   WRITE — PUT an object under the caller's prefix; ALLOWED for writer (DemoWriter),
//           DENIED for reader (DemoReader) — surfaced, not thrown.
// Prefix isolation (ABAC) still holds: everything targets the caller's own prefix, and
// the session policy blocks anything outside it (proven separately at the STS layer).
public sealed class StorageRoundtripEndpoint(
    CephSettings ceph, StsBroker sts, S3Gateway s3, AppDbContext db)
    : EndpointWithoutRequest<StorageDemoResult>
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
            await Send.ResponseAsync(
                new StorageDemoResult(caller.Subject, caller.Name, caller.Roles, "", "", "", "", false, "missing X-Id-Token", null),
                400, ct);
            return;
        }

        var prefix = $"{caller.Name}/";
        var roleArn = RoleResolver.ResolveRoleArn(caller.Roles);
        var sessionPolicy = SessionPolicy.ForCaller(ceph.Bucket, prefix, RoleResolver.CanWrite(caller.Roles));
        var creds = await sts.AssumeAsync(roleArn, caller.Subject, idToken, sessionPolicy, ct);

        // READ — both roles have GetObject; proves the reader isn't locked out, just read-only.
        var readKey = $"{prefix}welcome.txt";
        string readContent;
        try { readContent = await s3.GetAsync(creds, readKey, ct); }
        catch (AmazonS3Exception ex) { readContent = $"(read failed: {ex.ErrorCode})"; }

        // WRITE — RBAC gate. DemoWriter's role allows PutObject; DemoReader's does not.
        bool writeAllowed;
        string writeDetail;
        string? writeKey = $"{prefix}roundtrip-{Guid.NewGuid():N}.txt";
        try
        {
            await s3.PutAsync(creds, writeKey, $"walking-skeleton {DateTimeOffset.UtcNow:O}", ct);
            writeAllowed = true;
            writeDetail = $"created {writeKey}";
            db.AuditEntries.Add(new AuditEntry
            {
                At = DateTimeOffset.UtcNow,
                Subject = caller.Subject,
                RoleArn = roleArn,
                ObjectKey = writeKey,
            });
            await db.SaveChangesAsync(ct);
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            writeAllowed = false;
            writeKey = null;
            writeDetail = $"denied — role {roleArn} has no write capability (AccessDenied)";
        }

        await Send.OkAsync(
            new StorageDemoResult(
                caller.Subject, caller.Name, caller.Roles, roleArn, prefix,
                readKey, readContent, writeAllowed, writeDetail, writeKey),
            ct);
    }
}
