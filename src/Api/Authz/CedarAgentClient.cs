using System.Net.Http.Json;
using System.Text.Json;

namespace Api.Authz;

// ICedarClient over the cedar-agent REST API. Policies + the Action entity set are loaded at startup
// by CedarProvisioner; each call POSTs an is_authorized query whose principal/resource are readable
// (unregistered) uids and whose decision data rides in context.
public sealed class CedarAgentClient(HttpClient http) : ICedarClient
{
    public async Task<(bool Allow, string Reason)> IsAuthorizedAsync(
        string principal, string action, string resource, object context, CancellationToken ct)
    {
        var resp = await http.PostAsJsonAsync("/v1/is_authorized",
            new { principal, action, resource, context }, ct);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var root = doc.RootElement;
        var allow = root.GetProperty("decision").GetString() == "Allow";
        var reason = root.TryGetProperty("diagnostics", out var diag)
            && diag.TryGetProperty("reason", out var reasons)
            && reasons.ValueKind == JsonValueKind.Array && reasons.GetArrayLength() > 0
                ? reasons[0].GetString() ?? "" : "";
        return (allow, reason);
    }
}
