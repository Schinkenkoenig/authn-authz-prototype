using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class PolicyInputTests
{
    static CallerClaims Caller(string dept, string level, params string[] roles) =>
        new("sub", "u", roles, new Dictionary<string, string> { ["department"] = dept, ["level"] = level }, []);

    static PolicyInput In(StorageAction a, string key, CallerClaims c, bool breakGlass = false) =>
        PolicyInput.From(new AuthzRequest(c, a, key, new AuthzContext(breakGlass)));

    [Theory]
    [InlineData("public/x", 1)]
    [InlineData("internal/finance/x", 2)]
    [InlineData("classified/x", 3)]
    [InlineData("unlabeled/x", 1)]      // unknown prefix defaults to public
    public void Classification_comes_from_the_top_prefix(string key, int expected) =>
        Assert.Equal(expected, In(StorageAction.Read, key, Caller("finance", "2")).Classification);

    [Theory]
    [InlineData("internal/finance/report.txt", "finance")]
    [InlineData("classified/x", "x")]   // 2nd segment even if it is a file
    [InlineData("solo", "")]            // no 2nd segment
    public void Owner_department_is_the_second_path_segment(string key, string expected) =>
        Assert.Equal(expected, In(StorageAction.Write, key, Caller("finance", "2")).OwnerDepartment);

    [Theory]
    [InlineData("internal/frozen/x", true)]
    [InlineData("internal/finance/frozen/y", true)]
    [InlineData("frozen/x", true)]
    [InlineData("internal/finance/notfrozen.txt", false)]
    public void Frozen_is_a_frozen_path_segment(string key, bool expected) =>
        Assert.Equal(expected, In(StorageAction.Write, key, Caller("finance", "2")).Frozen);

    [Fact]
    public void Caller_fields_and_context_map_across()
    {
        var p = In(StorageAction.Read, "classified/x", Caller("hr", "1", "incident_responder"), breakGlass: true);
        Assert.Equal(1, p.Level);
        Assert.Equal("hr", p.CallerDepartment);
        Assert.Contains("incident_responder", p.Roles);
        Assert.True(p.BreakGlass);
        Assert.Equal("read", p.Action);
    }

    [Fact]
    public void Missing_level_is_zero_and_missing_department_is_empty()
    {
        var c = new CallerClaims("s", "u", [], new Dictionary<string, string>(), []);
        var p = PolicyInput.From(new AuthzRequest(c, StorageAction.Write, "public/x"));
        Assert.Equal(0, p.Level);
        Assert.Equal("", p.CallerDepartment);
        Assert.False(p.BreakGlass);   // null context
    }
}
