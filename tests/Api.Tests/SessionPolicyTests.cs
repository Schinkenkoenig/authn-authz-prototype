using System.Text.Json;
using Api.Authz;

namespace Api.Tests;

public class SessionPolicyTests
{
    [Fact]
    public void Builds_prefix_scoped_policy()
    {
        var json = SessionPolicy.ForPrefix("demo", "alice/");
        using var doc = JsonDocument.Parse(json);
        var res = doc.RootElement.GetProperty("Statement")[0].GetProperty("Resource");
        Assert.Contains(
            "arn:aws:s3:::demo/alice/*",
            res.EnumerateArray().Select(e => e.GetString()));
    }
}
