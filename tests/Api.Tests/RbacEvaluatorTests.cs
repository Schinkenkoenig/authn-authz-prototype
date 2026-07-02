using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class RbacEvaluatorTests
{
    static CallerClaims User(string name) =>
        new("sub-" + name, name, [], new Dictionary<string, string>(), []);

    static readonly RbacConfig Config = new(
        UserRoles: new Dictionary<string, IReadOnlyList<string>>
        {
            ["erin"] = ["editor"],
            ["carol"] = ["viewer"],
        },
        Permissions:
        [
            new RolePermission("editor", "projects/", [StorageAction.Read, StorageAction.Write]),
            new RolePermission("viewer", "shared/", [StorageAction.Read]),
        ]);

    [Fact]
    public void Role_grants_write_under_its_prefix()
    {
        var d = RbacEvaluator.Evaluate(User("erin"), StorageAction.Write, "projects/apollo/x.txt", Config);
        Assert.True(d.Permit);
    }

    [Fact]
    public void Viewer_cannot_write()
    {
        var d = RbacEvaluator.Evaluate(User("carol"), StorageAction.Write, "shared/x.txt", Config);
        Assert.False(d.Permit);
    }

    [Fact]
    public void Unknown_user_denied()
    {
        var d = RbacEvaluator.Evaluate(User("mallory"), StorageAction.Read, "shared/x.txt", Config);
        Assert.False(d.Permit);
        Assert.Contains("no roles", d.Reason);
    }
}
