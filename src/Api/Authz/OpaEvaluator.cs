namespace Api.Authz;

// Policy-as-code via OPA/Rego. Serializes PolicyInput into the Rego `input` document and reads the
// engine's decision. The policy logic (clearance, department, frozen-deny-override, break-glass)
// lives in authz.rego, not here.
public sealed class OpaEvaluator(IOpaClient client) : IExternalEvaluator
{
    public string Paradigm => "opa";

    public async Task<AuthzDecision> EvaluateAsync(AuthzRequest req, CancellationToken ct)
    {
        var p = PolicyInput.From(req);
        var input = new
        {
            action = p.Action,
            caller = new { level = p.Level, department = p.CallerDepartment, roles = p.Roles },
            resource = new { classification = p.Classification, owner_department = p.OwnerDepartment, frozen = p.Frozen },
            context = new { break_glass = p.BreakGlass },
        };
        var permit = await client.DecideAsync(input, ct);
        return new AuthzDecision(permit, $"OPA/Rego: {(permit ? "permit" : "deny")}", "opa");
    }
}
