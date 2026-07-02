using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;

namespace Api.Storage;

// Object I/O against Ceph RGW using the temporary, prefix-scoped credentials from
// the broker. Path-style addressing because RGW is reached by IP, not a vhost.
public sealed class S3Gateway(CephSettings ceph)
{
    AmazonS3Client Client(SessionAWSCredentials creds) =>
        new(creds, new AmazonS3Config
        {
            ServiceURL = ceph.ServiceUrl,
            ForcePathStyle = true,
            AuthenticationRegion = ceph.Region,
        });

    public async Task PutAsync(SessionAWSCredentials creds, string key, string content, CancellationToken ct)
    {
        using var s3 = Client(creds);
        await s3.PutObjectAsync(new PutObjectRequest
        {
            BucketName = ceph.Bucket,
            Key = key,
            ContentBody = content,
        }, ct);
    }

    public async Task<string> GetAsync(SessionAWSCredentials creds, string key, CancellationToken ct)
    {
        using var s3 = Client(creds);
        using var resp = await s3.GetObjectAsync(new GetObjectRequest
        {
            BucketName = ceph.Bucket,
            Key = key,
        }, ct);
        using var reader = new StreamReader(resp.ResponseStream);
        return await reader.ReadToEndAsync(ct);
    }
}
