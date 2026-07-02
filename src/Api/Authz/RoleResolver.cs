namespace Api.Authz;

// RBAC: map the caller's realm roles to the Ceph IAM role the API assumes on their behalf.
public static class RoleResolver
{
    public static string ResolveRoleArn(IReadOnlyCollection<string> roles)
    {
        if (roles.Contains("writer"))
            return "arn:aws:iam:::role/DemoWriter";
        if (roles.Contains("reader"))
            return "arn:aws:iam:::role/DemoReader";
        throw new UnauthorizedAccessException("caller has no storage role (reader/writer)");
    }

    // The write capability the session policy grants — the enforced RBAC distinction.
    public static bool CanWrite(IReadOnlyCollection<string> roles) => roles.Contains("writer");
}
