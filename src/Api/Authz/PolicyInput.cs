using Api.Auth;

namespace Api.Authz;

// The decision data both policy-as-code engines evaluate, derived once from the request. Classification
// is inferred from the key's top folder; owner-department from the second path segment; a `frozen`
// path segment marks a legal hold. Caller level/department come from token attributes; roles and the
// break-glass flag pass through. Serialized into OPA `input` and Cedar `context`.
public sealed record PolicyInput(
    string Action,
    int Classification,
    string OwnerDepartment,
    bool Frozen,
    int Level,
    string CallerDepartment,
    IReadOnlyList<string> Roles,
    bool BreakGlass)
{
    static readonly Dictionary<string, int> ClassByPrefix =
        new() { ["public"] = 1, ["internal"] = 2, ["classified"] = 3 };

    public static PolicyInput From(AuthzRequest req)
    {
        var segments = req.Resource.Split('/');
        var top = segments.Length > 0 ? segments[0] : "";
        var classification = ClassByPrefix.TryGetValue(top, out var c) ? c : 1;   // unknown → public
        var owner = segments.Length > 1 ? segments[1] : "";
        var frozen = ("/" + req.Resource).Contains("/frozen/");

        var attrs = req.Caller.Attributes;
        var level = attrs.TryGetValue("level", out var lv) && int.TryParse(lv, out var l) ? l : 0;
        var dept = attrs.TryGetValue("department", out var d) ? d : "";

        var action = req.Action switch
        {
            StorageAction.Read => "read",
            StorageAction.Write => "write",
            _ => "list",
        };

        return new PolicyInput(action, classification, owner, frozen, level, dept,
            req.Caller.Roles, req.Context?.BreakGlass ?? false);
    }
}
