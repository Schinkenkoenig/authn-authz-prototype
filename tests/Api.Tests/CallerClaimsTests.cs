using System.Security.Claims;
using Api.Auth;

namespace Api.Tests;

public class CallerClaimsTests
{
    // Mirrors the raw Keycloak access-token shape (MapInboundClaims=false):
    // realm roles arrive nested under a single `realm_access` JSON claim.
    static ClaimsPrincipal Principal(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, "Bearer"));

    [Fact]
    public void Extracts_subject_name_and_realm_roles()
    {
        var caller = CallerClaims.FromPrincipal(Principal(
            new Claim("sub", "alice-sub-123"),
            new Claim("preferred_username", "alice"),
            new Claim("realm_access", """{"roles":["reader","default-roles-authn-authz"]}""")));

        Assert.Equal("alice-sub-123", caller.Subject);
        Assert.Equal("alice", caller.Name);
        Assert.Contains("reader", caller.Roles);
    }

    [Fact]
    public void Extracts_attributes_and_storage_grants()
    {
        var caller = CallerClaims.FromPrincipal(Principal(
            new Claim("sub", "bob-sub"),
            new Claim("preferred_username", "bob"),
            new Claim("department", "engineering"),
            new Claim("level", "3"),
            new Claim("storage_grants", "rw:projects/apollo/"),
            new Claim("storage_grants", "r:shared/")));

        Assert.Equal("engineering", caller.Attributes["department"]);
        Assert.Equal("3", caller.Attributes["level"]);
        Assert.Equal(new[] { "rw:projects/apollo/", "r:shared/" }, caller.StorageGrants);
    }
}
