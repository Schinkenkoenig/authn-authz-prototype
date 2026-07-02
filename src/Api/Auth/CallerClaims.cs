using System.Security.Claims;
using System.Text.Json;

namespace Api.Auth;

// The validated identity, reduced to what the PDP needs: who the caller is and
// which realm roles they hold. Keycloak nests realm roles under a `realm_access`
// JSON claim; this is the one place that shape is decoded.
public sealed record CallerClaims(string Subject, string Name, IReadOnlyList<string> Roles)
{
    public static CallerClaims FromPrincipal(ClaimsPrincipal principal)
    {
        var subject = principal.FindFirstValue("sub") ?? "";
        var name = principal.FindFirstValue("preferred_username") ?? subject;
        return new CallerClaims(subject, name, RealmRoles(principal));
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
