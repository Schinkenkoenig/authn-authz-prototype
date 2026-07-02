using Api.Data;

namespace Api.Authz;

// The one shared world (spec §4): one prefix namespace + one roster, each paradigm's sweet-spot
// scenario a slice of it. Idempotent — seeds only when empty. Usernames are the principal keys
// for RBAC/ACL so seed data reads clearly; ABAC/claims key off attributes/token grants.
public static class AuthzSeeder
{
    public static void Seed(AppDbContext db)
    {
        if (db.RbacUserRoles.Any()) return;

        // RBAC — few reusable roles; bob & erin share 'editor' (role reuse is the sweet spot).
        db.RbacUserRoles.AddRange(
            new RbacUserRoleRow { Username = "alice", Role = "auditor" },
            new RbacUserRoleRow { Username = "bob", Role = "editor" },
            new RbacUserRoleRow { Username = "carol", Role = "viewer" },
            new RbacUserRoleRow { Username = "dave", Role = "admin" },
            new RbacUserRoleRow { Username = "erin", Role = "editor" });

        db.RbacRolePermissions.AddRange(
            new RbacRolePermissionRow { Role = "viewer", Prefix = "shared/", Actions = "Read,List" },
            new RbacRolePermissionRow { Role = "editor", Prefix = "projects/", Actions = "Read,Write,List" },
            new RbacRolePermissionRow { Role = "editor", Prefix = "shared/", Actions = "Read,List" },
            new RbacRolePermissionRow { Role = "auditor", Prefix = "finance/", Actions = "Read,List" },
            new RbacRolePermissionRow { Role = "auditor", Prefix = "hr/", Actions = "Read,List" },
            new RbacRolePermissionRow { Role = "auditor", Prefix = "engineering/", Actions = "Read,List" },
            new RbacRolePermissionRow { Role = "admin", Prefix = "*", Actions = "Read,Write,List" });

        // ABAC — rw under your own department; level >= 3 may read hr/.
        db.AbacRules.AddRange(
            new AbacRuleRow { ConditionsJson = "[]", PrefixTemplate = "{department}/", Actions = "Read,Write,List" },
            new AbacRuleRow
            {
                ConditionsJson = """[{"Attribute":"level","Op":"gte","Value":"3"}]""",
                PrefixTemplate = "hr/",
                Actions = "Read,List",
            });

        // ACL — explicit per-prefix lists + a wildcard.
        db.AclEntries.AddRange(
            new AclEntryRow { Prefix = "shared/", Principal = "*", Actions = "Read,List" },
            new AclEntryRow { Prefix = "shared/announcements/", Principal = "dave", Actions = "Read,Write,List" },
            new AclEntryRow { Prefix = "projects/apollo/", Principal = "bob", Actions = "Read,Write,List" },
            new AclEntryRow { Prefix = "finance/", Principal = "erin", Actions = "Read,Write,List" });

        db.SaveChanges();
    }
}
