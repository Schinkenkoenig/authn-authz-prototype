using System.Text;

namespace Api.Authz;

// Startup provisioning of OPA: PUT the Rego module. Fail-fast — an unreachable engine or a policy
// that OPA rejects throws and the app refuses to start. Returns a ready IOpaClient.
public static class OpaProvisioner
{
    public static async Task<IOpaClient> ProvisionAsync(string apiUrl, string rego, CancellationToken ct)
    {
        var http = new HttpClient { BaseAddress = new Uri(apiUrl) };
        var resp = await http.PutAsync("/v1/policies/authz",
            new StringContent(rego, Encoding.UTF8, "text/plain"), ct);
        resp.EnsureSuccessStatusCode();
        return new OpaClient(http);
    }
}
