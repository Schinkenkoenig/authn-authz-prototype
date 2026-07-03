using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class OpaEvaluatorTests
{
    sealed class StubOpa(bool permit) : IOpaClient
    {
        public object? LastInput;
        public Task<bool> DecideAsync(object input, CancellationToken ct)
        {
            LastInput = input;
            return Task.FromResult(permit);
        }
    }

    static AuthzRequest Req() => new(
        new CallerClaims("s", "carol", ["incident_responder"],
            new Dictionary<string, string> { ["department"] = "hr", ["level"] = "1" }, []),
        StorageAction.Read, "classified/x", new AuthzContext(true));

    [Fact]
    public void Paradigm_is_opa() => Assert.Equal("opa", new OpaEvaluator(new StubOpa(true)).Paradigm);

    [Fact]
    public async Task Permit_flows_through()
    {
        var d = await new OpaEvaluator(new StubOpa(true)).EvaluateAsync(Req(), CancellationToken.None);
        Assert.True(d.Permit);
        Assert.Equal("opa", d.Paradigm);
    }

    [Fact]
    public async Task Deny_flows_through()
    {
        var d = await new OpaEvaluator(new StubOpa(false)).EvaluateAsync(Req(), CancellationToken.None);
        Assert.False(d.Permit);
    }
}
