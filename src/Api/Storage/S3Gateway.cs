using Amazon.S3;
using Amazon.S3.Model;

namespace Api.Storage;

// Object I/O against Ceph RGW. Credentials are NOT passed here: the AWS SDK resolves them
// from the environment via its web-identity provider (AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE),
// assuming the broad service role and refreshing automatically. This gateway holds one client
// with the service identity; per-user authorization is decided by the API before calling in.
// Path-style addressing because RGW is reached by endpoint/IP, not a vhost.
public sealed class S3Gateway(CephSettings ceph)
{
    readonly AmazonS3Client _client = new(new AmazonS3Config
    {
        ServiceURL = ceph.ServiceUrl,
        ForcePathStyle = true,
        AuthenticationRegion = ceph.Region,
    });

    public async Task PutAsync(string key, string content, CancellationToken ct) =>
        await _client.PutObjectAsync(new PutObjectRequest
        {
            BucketName = ceph.Bucket,
            Key = key,
            ContentBody = content,
        }, ct);

    public async Task<string> GetAsync(string key, CancellationToken ct)
    {
        using var resp = await _client.GetObjectAsync(new GetObjectRequest
        {
            BucketName = ceph.Bucket,
            Key = key,
        }, ct);
        using var reader = new StreamReader(resp.ResponseStream);
        return await reader.ReadToEndAsync(ct);
    }
}
