using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class AuthzDispatcherTests
{
    static readonly AuthzConfig Config = new(
        new RbacConfig(new Dictionary<string, IReadOnlyList<string>> { ["bob"] = ["editor"] },
            [new RolePermission("editor", "projects/", [StorageAction.Write])]),
        new AbacConfig([]),
        new AclConfig([]));

    static AuthzRequest Req(string resource) =>
        new(new CallerClaims("sub", "bob", [], new Dictionary<string, string>(), []), StorageAction.Write, resource);

    [Theory]
    [InlineData(null, "rbac")]        // absent → default
    [InlineData("", "rbac")]          // empty → default
    [InlineData("nonsense", "rbac")]  // unknown → default
    [InlineData("acl", "acl")]        // known → itself
    public void Resolve_falls_back_to_default(string? selector, string expected) =>
        Assert.Equal(expected, AuthzDispatcher.Resolve(selector));

    [Fact]
    public void Decide_routes_to_named_paradigm()
    {
        var d = AuthzDispatcher.Decide("rbac", Req("projects/apollo/x"), Config);
        Assert.True(d.Permit);
        Assert.Equal("rbac", d.Paradigm);
    }
}
