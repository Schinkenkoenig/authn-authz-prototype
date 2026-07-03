using System.Text;

namespace Api.Authz;

// Startup provisioning of cedar-agent: PUT the policies and the entity (Action) set. Fail-fast.
// Returns a ready ICedarClient.
public static class CedarProvisioner
{
    public static async Task<ICedarClient> ProvisionAsync(
        string apiUrl, string policiesJson, string entitiesJson, CancellationToken ct)
    {
        var http = new HttpClient { BaseAddress = new Uri(apiUrl) };
        (await http.PutAsync("/v1/policies",
            new StringContent(policiesJson, Encoding.UTF8, "application/json"), ct)).EnsureSuccessStatusCode();
        (await http.PutAsync("/v1/data",
            new StringContent(entitiesJson, Encoding.UTF8, "application/json"), ct)).EnsureSuccessStatusCode();
        return new CedarAgentClient(http);
    }
}
