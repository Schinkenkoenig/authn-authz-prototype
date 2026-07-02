using System.Security.Claims;
using System.Text.Json;

namespace Api.Auth;

// The validated identity, reduced to what the paradigms need. Realm roles stay nested under
// Keycloak's `realm_access` claim (informational — shown by /whoami; RBAC assignment lives in
// the DB, not the token). ABAC reads `Attributes`; claim-based reads `StorageGrants`.
public sealed record CallerClaims(
    string Subject,
    string Name,
    IReadOnlyList<string> Roles,
    IReadOnlyDictionary<string, string> Attributes,
    IReadOnlyList<string> StorageGrants)
{
    // The fixed attribute set the ABAC showcase reasons over. Adding an attribute the rules
    // need means adding its claim name here.
    static readonly string[] AttributeClaims = ["department", "level"];

    public static CallerClaims FromPrincipal(ClaimsPrincipal principal)
    {
        var subject = principal.FindFirstValue("sub") ?? "";
        var name = principal.FindFirstValue("preferred_username") ?? subject;

        var attributes = new Dictionary<string, string>();
        foreach (var claim in AttributeClaims)
        {
            var value = principal.FindFirstValue(claim);
            if (value is not null)
                attributes[claim] = value;
        }

        var grants = principal.FindAll("storage_grants").Select(c => c.Value).ToArray();

        return new CallerClaims(subject, name, RealmRoles(principal), attributes, grants);
    }

    static IReadOnlyList<string> RealmRoles(ClaimsPrincipal principal)
    {
        var realmAccess = principal.FindFirstValue("realm_access");
        if (string.IsNullOrEmpty(realmAccess))
            return [];

        using var doc = JsonDocument.Parse(realmAccess);
        if (!doc.RootElement.TryGetProperty("roles", out var roles))
            return [];

        return roles.EnumerateArray().Select(r => r.GetString() ?? "").ToArray();
    }
}
