using System.Text.Json;
using Api.Authz;

namespace Api.Tests;

public class SessionPolicyTests
{
    static string[] Actions(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("Statement")[0].GetProperty("Action")
            .EnumerateArray().Select(e => e.GetString()!).ToArray();
    }

    static string[] Resources(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("Statement")[0].GetProperty("Resource")
            .EnumerateArray().Select(e => e.GetString()!).ToArray();
    }

    [Fact]
    public void Scopes_resource_to_the_caller_prefix()
    {
        var json = SessionPolicy.ForCaller("demo", "alice/", canWrite: false);
        Assert.Contains("arn:aws:s3:::demo/alice/*", Resources(json));
    }

    [Fact]
    public void Reader_gets_read_only_actions()
    {
        var actions = Actions(SessionPolicy.ForCaller("demo", "alice/", canWrite: false));
        Assert.Contains("s3:GetObject", actions);
        Assert.DoesNotContain("s3:PutObject", actions);
    }

    [Fact]
    public void Writer_gets_read_and_write_actions()
    {
        var actions = Actions(SessionPolicy.ForCaller("demo", "bob/", canWrite: true));
        Assert.Contains("s3:GetObject", actions);
        Assert.Contains("s3:PutObject", actions);
    }
}
