using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class AuthzContextTests
{
    [Fact]
    public void Request_context_defaults_to_null()
    {
        var caller = new CallerClaims("s", "n", [], new Dictionary<string, string>(), []);
        var req = new AuthzRequest(caller, StorageAction.Read, "k");
        Assert.Null(req.Context);
    }

    [Fact]
    public void Request_carries_break_glass_when_supplied()
    {
        var caller = new CallerClaims("s", "n", [], new Dictionary<string, string>(), []);
        var req = new AuthzRequest(caller, StorageAction.Read, "k", new AuthzContext(BreakGlass: true));
        Assert.True(req.Context!.BreakGlass);
    }
}
