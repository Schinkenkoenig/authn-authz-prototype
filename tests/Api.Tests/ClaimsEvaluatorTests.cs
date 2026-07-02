using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class ClaimsEvaluatorTests
{
    static CallerClaims User(params string[] grants) =>
        new("sub", "u", [], new Dictionary<string, string>(), grants);

    [Fact]
    public void Rw_grant_permits_write()
    {
        var d = ClaimsEvaluator.Evaluate(User("rw:projects/apollo/"), StorageAction.Write, "projects/apollo/x");
        Assert.True(d.Permit);
    }

    [Fact]
    public void Read_grant_does_not_permit_write()
    {
        var d = ClaimsEvaluator.Evaluate(User("r:finance/"), StorageAction.Write, "finance/x");
        Assert.False(d.Permit);
    }

    [Fact]
    public void Read_grant_permits_read_and_list()
    {
        Assert.True(ClaimsEvaluator.Evaluate(User("r:finance/"), StorageAction.Read, "finance/x").Permit);
        Assert.True(ClaimsEvaluator.Evaluate(User("r:finance/"), StorageAction.List, "finance/").Permit);
    }

    [Fact]
    public void Wildcard_grant_permits_everything()
    {
        Assert.True(ClaimsEvaluator.Evaluate(User("rw:*"), StorageAction.Write, "anything/x").Permit);
    }

    [Fact]
    public void No_grant_denied()
    {
        Assert.False(ClaimsEvaluator.Evaluate(User(), StorageAction.Read, "finance/x").Permit);
    }
}
