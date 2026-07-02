using Amazon.Runtime;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;

namespace Api.Storage;

// The PDP's hand-off to Ceph: exchange the caller's OIDC ID token for temporary,
// prefix-scoped S3 credentials via AssumeRoleWithWebIdentity. The inline session
// policy narrows the assumed role to the caller's own prefix (proven in Task 3).
public sealed class StsBroker(CephSettings ceph)
{
    public async Task<SessionAWSCredentials> AssumeAsync(
        string roleArn, string sessionName, string idToken, string sessionPolicyJson, CancellationToken ct)
    {
        using var sts = new AmazonSecurityTokenServiceClient(
            new AnonymousAWSCredentials(),
            new AmazonSecurityTokenServiceConfig { ServiceURL = ceph.ServiceUrl, AuthenticationRegion = ceph.Region });

        var resp = await sts.AssumeRoleWithWebIdentityAsync(new AssumeRoleWithWebIdentityRequest
        {
            RoleArn = roleArn,
            RoleSessionName = sessionName,
            WebIdentityToken = idToken,
            Policy = sessionPolicyJson,
            DurationSeconds = 900,
        }, ct);

        var c = resp.Credentials;
        return new SessionAWSCredentials(c.AccessKeyId, c.SecretAccessKey, c.SessionToken);
    }
}
