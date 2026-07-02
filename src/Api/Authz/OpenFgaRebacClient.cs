using OpenFga.Sdk.Client;
using OpenFga.Sdk.Client.Model;

namespace Api.Authz;

// IRebacClient over a configured OpenFgaClient (the provisioner has already baked in the store id
// and authorization model id). One Check call per decision.
public sealed class OpenFgaRebacClient(OpenFgaClient client) : IRebacClient
{
    public async Task<bool> CheckAsync(string user, string relation, string obj, CancellationToken ct)
    {
        var res = await client.Check(
            new ClientCheckRequest { User = user, Relation = relation, Object = obj },
            cancellationToken: ct);
        return res.Allowed ?? false;
    }
}

// Stand-in when OpenFGA is not configured (no Openfga:ApiUrl): the four in-process paradigms still
// run; selecting rebac simply denies.
public sealed class UnconfiguredRebacClient : IRebacClient
{
    public Task<bool> CheckAsync(string user, string relation, string obj, CancellationToken ct) =>
        Task.FromResult(false);
}
