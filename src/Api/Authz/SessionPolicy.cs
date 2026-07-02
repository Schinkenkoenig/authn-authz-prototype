using System.Text.Json;

namespace Api.Authz;

// The effective permission the API (PDP) grants for one request, handed to
// AssumeRoleWithWebIdentity as the inline session policy. It encodes BOTH layers:
//   RBAC  — which actions (read-only vs read+write), from the caller's role.
//   ABAC  — which prefix (the caller's own), from the caller's identity.
//
// On this Ceph setup the inline session policy is the SOLE enforcer: the assumed role
// lives in the bucket-owner account, so the role's own permission-policy actions are not
// enforced (owner bypass) — see the STS verdicts note. Therefore every assume-role MUST
// carry one of these; an empty/omitted policy fails OPEN to full bucket access.
public static class SessionPolicy
{
    public static string ForCaller(string bucket, string prefix, bool canWrite)
    {
        string[] actions = canWrite
            ? ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
            : ["s3:GetObject"];

        var policy = new
        {
            Version = "2012-10-17",
            Statement = new[]
            {
                new
                {
                    Effect = "Allow",
                    Action = actions,
                    Resource = new[] { $"arn:aws:s3:::{bucket}/{prefix}*" }
                }
            }
        };
        return JsonSerializer.Serialize(policy);
    }
}
