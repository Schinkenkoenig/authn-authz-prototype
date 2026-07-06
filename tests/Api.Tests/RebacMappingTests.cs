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
}
