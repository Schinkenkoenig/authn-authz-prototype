using System.Net.Http.Json;
using System.Text.Json;

namespace Api.Authz;

// IOpaClient over the OPA REST API. The policy is loaded at startup by OpaProvisioner; each call
// POSTs the input document to the decision rule and reads decision.permit.
public sealed class OpaClient(HttpClient http) : IOpaClient
{
    public async Task<bool> DecideAsync(object input, CancellationToken ct)
    {
        var resp = await http.PostAsJsonAsync("/v1/data/authz/decision", new { input }, ct);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        return doc.RootElement.TryGetProperty("result", out var result)
            && result.TryGetProperty("permit", out var permit)
            && permit.ValueKind == JsonValueKind.True;
    }
}
