namespace Api.Data;

// Seeded authorization config, read into in-memory structs at startup. Multi-value fields are
// stored as simple strings (Actions CSV like "Read,Write"; ABAC conditions as JSON) so the
// schema stays flat and the parsing lives in AuthzConfigStore.
public sealed class RbacUserRoleRow
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    public string Role { get; set; } = "";
}

public sealed class RbacRolePermissionRow
{
    public int Id { get; set; }
    public string Role { get; set; } = "";
    public string Prefix { get; set; } = "";
    public string Actions { get; set; } = ""; // CSV of StorageAction
}

public sealed class AbacRuleRow
{
    public int Id { get; set; }
    public string ConditionsJson { get; set; } = "[]"; // JSON array of {Attribute,Op,Value}
    public string PrefixTemplate { get; set; } = "";
    public string Actions { get; set; } = ""; // CSV of StorageAction
}

public sealed class AclEntryRow
{
    public int Id { get; set; }
    public string Prefix { get; set; } = "";
    public string Principal { get; set; } = ""; // username or "*"
    public string Actions { get; set; } = ""; // CSV of StorageAction
}
