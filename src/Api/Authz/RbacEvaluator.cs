using Api.Auth;

namespace Api.Authz;

// RBAC config lives in the DB (role→permission and user→role), keyed by username for legible
// seed data. Sweet spot: many users share few roles, so onboarding is one user_roles row.
public sealed record RolePermission(string Role, string Prefix, IReadOnlyList<StorageAction> Actions);

public sealed record RbacConfig(
    IReadOnlyDictionary<string, IReadOnlyList<string>> UserRoles,
    IReadOnlyList<RolePermission> Permissions);

public static class RbacEvaluator
{
    public static AuthzDecision Evaluate(CallerClaims caller, StorageAction action, string resource, RbacConfig cfg)
    {
        if (!cfg.UserRoles.TryGetValue(caller.Name, out var roles) || roles.Count == 0)
            return new(false, $"no roles assigned to '{caller.Name}'", "rbac");

        foreach (var perm in cfg.Permissions)
            if (roles.Contains(perm.Role) && perm.Actions.Contains(action) && PrefixMatch.Covers(perm.Prefix, resource))
                return new(true, $"role '{perm.Role}' grants {action} on '{perm.Prefix}'", "rbac");

        return new(false, $"role(s) [{string.Join(", ", roles)}] grant no {action} on '{resource}'", "rbac");
    }
}
