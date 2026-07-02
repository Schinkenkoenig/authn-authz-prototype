using System.Text.Json;

namespace Api.Authz;

// ABAC: build the inline session policy handed to AssumeRoleWithWebIdentity so the
// temporary credentials are narrowed to a single object prefix, regardless of how
// broad the assumed role's permission policy is. Proven honored by Ceph Squid in Task 3.
public static class SessionPolicy
{
    public static string ForPrefix(string bucket, string prefix)
    {
        var policy = new
        {
            Version = "2012-10-17",
            Statement = new[]
            {
                new
                {
                    Effect = "Allow",
                    Action = new[] { "s3:GetObject", "s3:PutObject" },
                    Resource = new[] { $"arn:aws:s3:::{bucket}/{prefix}*" }
                }
            }
        };
        return JsonSerializer.Serialize(policy);
    }
}
