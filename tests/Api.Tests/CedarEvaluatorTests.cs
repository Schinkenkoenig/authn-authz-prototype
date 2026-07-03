using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class CedarEvaluatorTests
{
    sealed class StubCedar(bool allow, string reason) : ICedarClient
    {
        public string? LastAction;
        public Task<(bool Allow, string Reason)> IsAuthorizedAsync(
            string principal, string action, string resource, object context, CancellationToken ct)
        {
            LastAction = action;
            return Task.FromResult((allow, reason));
        }
    }

    static AuthzRequest Req() => new(
        new CallerClaims("s", "bob", [],
            new Dictionary<string, string> { ["department"] = "engineering", ["level"] = "3" }, []),
        StorageAction.Read, "classified/x");

    [Fact]
    public void Paradigm_is_cedar() =>
        Assert.Equal("cedar", new CedarEvaluator(new StubCedar(true, "")).Paradigm);

    [Fact]
    public async Task Permit_and_reason_flow_through()
    {
        var d = await new CedarEvaluator(new StubCedar(true, "r1-read-clearance")).EvaluateAsync(Req(), CancellationToken.None);
        Assert.True(d.Permit);
        Assert.Equal("cedar", d.Paradigm);
        Assert.Contains("r1-read-clearance", d.Reason);
    }

    [Fact]
    public async Task Deny_flows_through()
    {
        var d = await new CedarEvaluator(new StubCedar(false, "")).EvaluateAsync(Req(), CancellationToken.None);
        Assert.False(d.Permit);
    }

    [Fact]
    public async Task Action_is_mapped_to_the_cedar_action_uid()
    {
        var stub = new StubCedar(true, "");
        await new CedarEvaluator(stub).EvaluateAsync(Req(), CancellationToken.None);
        Assert.Equal("Action::\"read\"", stub.LastAction);
    }
}
