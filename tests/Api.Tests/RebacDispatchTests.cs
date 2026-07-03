using Api.Auth;
using Api.Authz;

namespace Api.Tests;

// DecideAsync now dispatches external paradigms from a paradigm→evaluator dictionary. These tests
// cover the routing/wrapping; a stub stands in for OpenFGA (the real graph Check is an e2e concern).
public class RebacDispatchTests
{
    sealed class StubRebac(bool allowed) : IRebacClient
    {
        public Task<bool> CheckAsync(string user, string relation, string obj, CancellationToken ct) =>
            Task.FromResult(allowed);
    }

    static IReadOnlyDictionary<string, IExternalEvaluator> Engines(IRebacClient rebac) =>
        new Dictionary<string, IExternalEvaluator> { ["rebac"] = new RebacExternalEvaluator(rebac) };

    static readonly IReadOnlyDictionary<string, IExternalEvaluator> Unconfigured =
        new Dictionary<string, IExternalEvaluator> { ["rebac"] = new UnconfiguredEvaluator("rebac") };

    static readonly AuthzConfig Config = new(
        new RbacConfig(new Dictionary<string, IReadOnlyList<string>> { ["bob"] = ["editor"] },
            [new RolePermission("editor", "projects/", [StorageAction.Write])]),
        new AbacConfig([]),
        new AclConfig([]));

    static AuthzRequest Req(StorageAction action, string resource) =>
        new(new CallerClaims("sub", "bob", [], new Dictionary<string, string>(), []), action, resource);

    [Fact]
    public void Rebac_cedar_opa_are_registered_paradigms()
    {
        Assert.Contains("rebac", AuthzDispatcher.Paradigms);
        Assert.Contains("cedar", AuthzDispatcher.Paradigms);
        Assert.Contains("opa", AuthzDispatcher.Paradigms);
    }

    [Fact]
    public async Task Rebac_permit_flows_through_from_the_engine()
    {
        var d = await AuthzDispatcher.DecideAsync("rebac", Req(StorageAction.Read, "projects/apollo/x"),
            Config, Engines(new StubRebac(true)), CancellationToken.None);
        Assert.True(d.Permit);
        Assert.Equal("rebac", d.Paradigm);
    }

    [Fact]
    public async Task Rebac_deny_flows_through_from_the_engine()
    {
        var d = await AuthzDispatcher.DecideAsync("rebac", Req(StorageAction.Write, "projects/apollo/x"),
            Config, Engines(new StubRebac(false)), CancellationToken.None);
        Assert.False(d.Permit);
    }

    [Fact]
    public async Task Unconfigured_external_paradigm_denies_rather_than_throws()
    {
        var d = await AuthzDispatcher.DecideAsync("rebac", Req(StorageAction.Read, "projects/apollo/x"),
            Config, Unconfigured, CancellationToken.None);
        Assert.False(d.Permit);
    }

    [Fact]
    public async Task Sync_paradigm_routes_to_the_pure_evaluator_ignoring_the_map()
    {
        var d = await AuthzDispatcher.DecideAsync("rbac", Req(StorageAction.Write, "projects/apollo/x"),
            Config, Unconfigured, CancellationToken.None);
        Assert.True(d.Permit);
        Assert.Equal("rbac", d.Paradigm);
    }
}
