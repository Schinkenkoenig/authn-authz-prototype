namespace Api.Authz;

// RBAC capability from the caller's realm roles. Under service-level IAM the API no longer
// assumes a per-user Ceph role; it enforces the caller's capability itself before doing I/O
// with the service identity. Writer beats reader.
public static class RoleResolver
{
    public static bool CanWrite(IReadOnlyCollection<string> roles) => roles.Contains("writer");
}
