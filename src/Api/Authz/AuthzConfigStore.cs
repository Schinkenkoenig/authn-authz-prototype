using System.Text.Json;
using Api.Data;
using Microsoft.EntityFrameworkCore;

namespace Api.Authz;

// Loads seeded config once at startup into an immutable in-memory bundle the evaluators read.
// Keeping the load here (not in the evaluators) is what lets decision logic stay pure and
// DbContext-free. Read-only this spec; a reload path arrives with the config-editing playground.
public sealed class AuthzConfigStore
{
    public AuthzConfig Current { get; private set; } = new(
        new RbacConfig(new Dictionary<string, IReadOnlyList<string>>(), []),
        new AbacConfig([]),
        new AclConfig([]));

    public void Load(AppDbContext db)
    {
        var userRoles = db.RbacUserRoles.AsNoTracking().ToList()
            .GroupBy(r => r.Username)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(x => x.Role).ToList());

        var permissions = db.RbacRolePermissions.AsNoTracking().ToList()
            .Select(p => new RolePermission(p.Role, p.Prefix, ParseActions(p.Actions)))
            .ToList();

        var rules = db.AbacRules.AsNoTracking().ToList()
            .Select(r => new AbacRule(ParseConditions(r.ConditionsJson), r.PrefixTemplate, ParseActions(r.Actions)))
            .ToList();

        var acl = db.AclEntries.AsNoTracking().ToList()
            .Select(a => new AclEntry(a.Prefix, a.Principal, ParseActions(a.Actions)))
            .ToList();

        Current = new AuthzConfig(new RbacConfig(userRoles, permissions), new AbacConfig(rules), new AclConfig(acl));
    }

    public static IReadOnlyList<StorageAction> ParseActions(string csv) =>
        csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
           .Select(Enum.Parse<StorageAction>)
           .ToList();

    public static IReadOnlyList<AttrPredicate> ParseConditions(string json) =>
        string.IsNullOrWhiteSpace(json)
            ? []
            : JsonSerializer.Deserialize<List<AttrPredicate>>(json) ?? [];
}
