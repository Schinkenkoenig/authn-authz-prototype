using Api.Auth;

namespace Api.Authz;

// The relationship graph paradigm. Unlike the four in-process evaluators this one is NOT pure:
// the graph lives in OpenFGA, so a decision is an awaited network Check. Only the mapping onto
// that check (user object, relation, prefix object) is pure and unit-tested here; the graph
// logic (inheritance, group membership) is OpenFGA's and is covered by the e2e verify script.
//
// Resource → prefix object: a list prefix (ends in '/') maps to itself; an object key maps to the
// folder that contains it. OpenFGA's `viewer/editor from parent` then walks up the seeded chain.
public static class RebacEvaluator
{
    public static string RelationFor(StorageAction action) =>
        action == StorageAction.Write ? "editor" : "viewer";

    public static string PrefixObject(string resource)
    {
        var slash = resource.LastIndexOf('/');
        var prefix = slash < 0 ? "" : resource[..(slash + 1)];
        return "prefix:" + prefix;
    }

    public static string UserObject(string name) => "user:" + name;

    public static async Task<AuthzDecision> EvaluateAsync(
        CallerClaims caller, StorageAction action, string resource, IRebacClient client, CancellationToken ct)
    {
        var user = UserObject(caller.Name);
        var relation = RelationFor(action);
        var obj = PrefixObject(resource);

        var allowed = await client.CheckAsync(user, relation, obj, ct);
        if (allowed)
            return new(true, $"OpenFGA: {user} has {relation} on {obj}", "rebac");

        var reason = RebacSeeder.ModeledPrefixes.Contains(obj)
            ? $"OpenFGA: {user} lacks {relation} on {obj}"
            : $"OpenFGA: {obj} has no seeded tuple at this depth (unmodeled — not a policy decision)";
        return new(false, reason, "rebac");
    }
}
