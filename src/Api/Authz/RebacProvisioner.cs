using OpenFga.Sdk.Client;
using OpenFga.Sdk.Client.Model;

namespace Api.Authz;

// Startup provisioning of the OpenFGA store, analogous to the DB migrate→seed. Reuse the named
// store if the engine already has it (in-memory OpenFGA keeps it across API restarts, but loses it
// when the engine itself restarts), otherwise create the store and write the model + seed tuples.
// Fail-fast: an unreachable engine throws and the app refuses to start. Returns a client with the
// store id + authorization model id baked in, ready for Check.
public static class RebacProvisioner
{
    public static async Task<OpenFgaClient> ProvisionAsync(string apiUrl, string modelJson, CancellationToken ct)
    {
        var client = new OpenFgaClient(new ClientConfiguration { ApiUrl = apiUrl });

        var stores = await client.ListStores(null, cancellationToken: ct);
        var existing = stores.Stores?.FirstOrDefault(s => s.Name == RebacSeeder.StoreName);

        string modelId;
        if (existing is not null)
        {
            client.StoreId = existing.Id;
            var latest = await client.ReadLatestAuthorizationModel(cancellationToken: ct);
            modelId = latest?.AuthorizationModel?.Id
                ?? throw new InvalidOperationException(
                    $"OpenFGA store '{RebacSeeder.StoreName}' exists but has no authorization model");
        }
        else
        {
            var store = await client.CreateStore(
                new ClientCreateStoreRequest { Name = RebacSeeder.StoreName }, cancellationToken: ct);
            client.StoreId = store.Id;

            var model = await client.WriteAuthorizationModel(
                ClientWriteAuthorizationModelRequest.FromJson(modelJson), cancellationToken: ct);
            modelId = model.AuthorizationModelId;

            var writes = RebacSeeder.Tuples
                .Select(t => new ClientTupleKey { User = t.User, Relation = t.Relation, Object = t.Object })
                .ToList();
            await client.Write(
                new ClientWriteRequest { Writes = writes },
                new ClientWriteOptions { AuthorizationModelId = modelId }, ct);
        }

        client.AuthorizationModelId = modelId;
        return client;
    }
}
