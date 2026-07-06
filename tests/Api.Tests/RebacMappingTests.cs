using Api.Auth;
using Api.Authz;

namespace Api.Tests;

// The pure, engine-free part of ReBAC: how a storage request maps onto an OpenFGA check
// (user object, relation, prefix object). The relationship logic itself lives in OpenFGA and is
// covered by the e2e verify script.
public class RebacMappingTests
{
    [Theory]
    [InlineData(StorageAction.Read, "viewer")]
    [InlineData(StorageAction.List, "viewer")]
    [InlineData(StorageAction.Write, "editor")]
    public void Action_maps_to_relation(StorageAction action, string relation) =>
        Assert.Equal(relation, RebacEvaluator.RelationFor(action));

    [Fact]
    public void Object_key_maps_to_its_containing_prefix()
    {
        Assert.Equal("prefix:projects/apollo/specs/",
            RebacEvaluator.PrefixObject("projects/apollo/specs/design.md"));
    }

    [Fact]
    public void List_prefix_maps_to_itself()
    {
        Assert.Equal("prefix:projects/apollo/",
            RebacEvaluator.PrefixObject("projects/apollo/"));
    }

    [Fact]
    public void Top_level_key_has_empty_containing_prefix()
    {
        // No root prefix object exists in the seeded world, so this can only ever deny.
        Assert.Equal("prefix:", RebacEvaluator.PrefixObject("notes.txt"));
    }

    [Fact]
    public void User_name_maps_to_user_object() =>
        Assert.Equal("user:carol", RebacEvaluator.UserObject("carol"));

    [Fact]
    public void ModeledPrefixes_contains_every_prefix_wired_into_a_tuple()
    {
        var expected = new HashSet<string>
        {
            "prefix:projects/",
            "prefix:projects/apollo/",
            "prefix:projects/apollo/specs/",
            "prefix:shared/",
        };
        Assert.Equal(expected, RebacSeeder.ModeledPrefixes);
    }

    sealed class StubRebac(bool allowed) : IRebacClient
    {
        public Task<bool> CheckAsync(string user, string relation, string obj, CancellationToken ct) =>
            Task.FromResult(allowed);
    }

    static CallerClaims Caller(string name) =>
        new("sub", name, [], new Dictionary<string, string>(), []);

    [Fact]
    public async Task Deny_reason_for_a_modeled_prefix_says_the_user_lacks_the_relation()
    {
        var d = await RebacEvaluator.EvaluateAsync(
            Caller("carol"), StorageAction.Write, "projects/apollo/a.txt",
            new StubRebac(false), CancellationToken.None);

        Assert.False(d.Permit);
        Assert.Equal("OpenFGA: user:carol lacks editor on prefix:projects/apollo/", d.Reason);
    }

    [Fact]
    public async Task Deny_reason_for_an_unmodeled_prefix_flags_it_as_a_coverage_gap()
    {
        var d = await RebacEvaluator.EvaluateAsync(
            Caller("bob"), StorageAction.Write, "projects/apollo/specs/deep/nested.txt",
            new StubRebac(false), CancellationToken.None);

        Assert.False(d.Permit);
        Assert.Equal(
            "OpenFGA: prefix:projects/apollo/specs/deep/ has no seeded tuple at this depth (unmodeled — not a policy decision)",
            d.Reason);
    }

    [Fact]
    public async Task Permit_reason_is_unchanged()
    {
        var d = await RebacEvaluator.EvaluateAsync(
            Caller("carol"), StorageAction.Read, "projects/apollo/a.txt",
            new StubRebac(true), CancellationToken.None);

        Assert.True(d.Permit);
        Assert.Equal("OpenFGA: user:carol has viewer on prefix:projects/apollo/", d.Reason);
    }
}
