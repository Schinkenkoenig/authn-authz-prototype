using Api.Auth;
using Api.Authz;

namespace Api.Tests;

// DecideAsync is the async variant of the seam: it delegates the four pure paradigms to the sync
// Decide and awaits the ReBAC evaluator. These tests cover the routing/wrapping; a stub stands in
// for OpenFGA (the real graph Check is an e2e concern — see scripts/verify-authz.py).
public class RebacDispatchTests
{
    sealed class StubRebac(bool allowed) : IRebacClient
    {
        public Task<bool> CheckAsync(string user, string relation, string obj, CancellationToken ct) =>
            Task.FromResult(allowed);
    }

    static readonly AuthzConfig Config = new(
        new RbacConfig(new Dictionary<string, IReadOnlyList<string>> { ["bob"] = ["editor"] },
            [new RolePermission("editor", "projects/", [StorageAction.Write])]),
        new AbacConfig([]),
        new AclConfig([]));

    static AuthzRequest Req(StorageAction action, string resource) =>
        new(new CallerClaims("sub", "bob", [], new Dictionary<string, string>(), []), action, resource);

    [Fact]
    public void Rebac_is_a_registered_paradigm() =>
        Assert.Contains("rebac", AuthzDispatcher.Paradigms);

    [Fact]
    public async Task Rebac_permit_flows_through_from_the_engine()
    {
        var d = await AuthzDispatcher.DecideAsync("rebac", Req(StorageAction.Read, "projects/apollo/x"),
            Config, new StubRebac(true), CancellationToken.None);
        Assert.True(d.Permit);
        Assert.Equal("rebac", d.Paradigm);
    }

    [Fact]
    public async Task Rebac_deny_flows_through_from_the_engine()
    {
        var d = await AuthzDispatcher.DecideAsync("rebac", Req(StorageAction.Write, "projects/apollo/x"),
            Config, new StubRebac(false), CancellationToken.None);
        Assert.False(d.Permit);
    }

    [Fact]
    public async Task Rebac_without_a_client_denies_rather_than_throws()
    {
        var d = await AuthzDispatcher.DecideAsync("rebac", Req(StorageAction.Read, "projects/apollo/x"),
            Config, null, CancellationToken.None);
        Assert.False(d.Permit);
    }

    [Fact]
    public async Task Sync_paradigm_routes_to_the_pure_evaluator_ignoring_the_client()
    {
        var d = await AuthzDispatcher.DecideAsync("rbac", Req(StorageAction.Write, "projects/apollo/x"),
            Config, null, CancellationToken.None);
        Assert.True(d.Permit);
        Assert.Equal("rbac", d.Paradigm);
    }
}
