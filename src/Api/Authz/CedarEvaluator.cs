namespace Api.Authz;

// Policy-as-code via Cedar (cedar-agent). Because storage keys are dynamic, all decision data rides
// in the request context (proven in the spike); principal/resource are readable but unregistered
// uids. The policy logic lives in cedar-policies.json.
public sealed class CedarEvaluator(ICedarClient client) : IExternalEvaluator
{
    public string Paradigm => "cedar";

    public async Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct)
    {
        var p = PolicyInput.From(req);
        var context = new Dictionary<string, object>
        {
            ["classification"] = p.Classification,
            ["level"] = p.Level,
            ["caller_department"] = p.CallerDepartment,
            ["owner_department"] = p.OwnerDepartment,
            ["frozen"] = p.Frozen,
            ["roles"] = p.Roles,
            ["break_glass"] = p.BreakGlass,
        };
        var (allow, reason) = await client.IsAuthorizedAsync(
            $"User::\"{req.Caller.Name}\"", $"Action::\"{p.Action}\"", "Resource::\"obj\"", context, ct);
        var why = reason.Length > 0 ? $" [{reason}]" : "";
        return new AuthzDecision(allow, $"Cedar: {(allow ? "Allow" : "Deny")}{why}", "cedar");
    }
}
