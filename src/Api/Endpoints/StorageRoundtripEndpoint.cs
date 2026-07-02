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
    string Prefix,
    string ReadKey,
    string ReadContent,
    bool WriteAllowed,
    string WriteDetail,
    string? WriteKey);

// The API is the PDP+PEP. It authenticates the caller (access token, aud=api), then enforces
// authorization itself:
//   ABAC — every object key is under the caller's own prefix (cross-user access impossible by
//          construction).
//   RBAC — writes require the writer capability; readers are refused here (not by storage).
// Storage I/O uses the service identity (SDK web-identity creds, broad access) — the backend is
// dumb and swappable; no per-user STS.
public sealed class StorageRoundtripEndpoint(S3Gateway s3, AppDbContext db)
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
        var prefix = $"{caller.Name}/";

        // READ — any authenticated caller may read within their own prefix.
        var readKey = $"{prefix}welcome.txt";
        string readContent;
        try { readContent = await s3.GetAsync(readKey, ct); }
        catch (AmazonS3Exception ex) { readContent = $"(read failed: {ex.ErrorCode})"; }

        // WRITE — RBAC decided by the API, not the backend.
        bool writeAllowed = RoleResolver.CanWrite(caller.Roles);
        string writeDetail;
        string? writeKey = null;
        if (!writeAllowed)
        {
            writeDetail = $"denied by API — role(s) [{string.Join(", ", caller.Roles)}] have no write capability";
        }
        else
        {
            writeKey = $"{prefix}roundtrip-{Guid.NewGuid():N}.txt";
            await s3.PutAsync(writeKey, $"walking-skeleton {DateTimeOffset.UtcNow:O}", ct);
            writeDetail = $"created {writeKey}";
            db.AuditEntries.Add(new AuditEntry
            {
                At = DateTimeOffset.UtcNow,
                Subject = caller.Subject,
                RoleArn = "app-enforced",
                ObjectKey = writeKey,
            });
            await db.SaveChangesAsync(ct);
        }

        await Send.OkAsync(
            new StorageDemoResult(
                caller.Subject, caller.Name, caller.Roles, prefix,
                readKey, readContent, writeAllowed, writeDetail, writeKey),
            ct);
    }
}
