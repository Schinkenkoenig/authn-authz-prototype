using Api.Authz;

namespace Api.Tests;

public class AuthzConfigParseTests
{
    [Fact]
    public void Parses_action_csv()
    {
        var actions = AuthzConfigStore.ParseActions("Read, Write");
        Assert.Equal(new[] { StorageAction.Read, StorageAction.Write }, actions);
    }

    [Fact]
    public void Parses_empty_actions_to_empty()
    {
        Assert.Empty(AuthzConfigStore.ParseActions(""));
    }

    [Fact]
    public void Parses_conditions_json()
    {
        var conds = AuthzConfigStore.ParseConditions("""[{"Attribute":"level","Op":"gte","Value":"3"}]""");
        Assert.Single(conds);
        Assert.Equal("level", conds[0].Attribute);
        Assert.Equal("gte", conds[0].Op);
        Assert.Equal("3", conds[0].Value);
    }

    [Fact]
    public void Parses_empty_conditions_to_empty()
    {
        Assert.Empty(AuthzConfigStore.ParseConditions("[]"));
        Assert.Empty(AuthzConfigStore.ParseConditions(""));
    }
}
