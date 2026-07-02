using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class AclEvaluatorTests
{
    static CallerClaims User(string name) =>
        new("sub", name, [], new Dictionary<string, string>(), []);

    static readonly AclConfig Config = new(
    [
        new AclEntry("shared/", "*", [StorageAction.Read]),
        new AclEntry("projects/apollo/", "bob", [StorageAction.Read, StorageAction.Write]),
    ]);

    [Fact]
    public void Wildcard_principal_grants_everyone_read()
    {
        Assert.True(AclEvaluator.Evaluate(User("carol"), StorageAction.Read, "shared/notes.txt", Config).Permit);
    }

    [Fact]
    public void Named_principal_grants_only_that_user()
    {
        Assert.True(AclEvaluator.Evaluate(User("bob"), StorageAction.Write, "projects/apollo/x", Config).Permit);
        Assert.False(AclEvaluator.Evaluate(User("carol"), StorageAction.Write, "projects/apollo/x", Config).Permit);
    }

    [Fact]
    public void No_matching_entry_denied()
    {
        Assert.False(AclEvaluator.Evaluate(User("carol"), StorageAction.Write, "shared/notes.txt", Config).Permit);
    }
}
