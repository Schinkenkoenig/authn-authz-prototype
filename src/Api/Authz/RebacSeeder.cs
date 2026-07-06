namespace Api.Authz;

// One relationship tuple: (user | userset) --relation--> object. The ReBAC analogue of a config row.
public sealed record RebacTuple(string User, string Relation, string Object);

// The ReBAC seed world (spec §Seed world), written to OpenFGA at startup. Mirrors AuthzSeeder for
// the in-process paradigms, but the "config" here is a relationship graph, not DB rows. Usernames
// match the Keycloak realm (alice/bob/carol/dave/erin). Shows hierarchy inheritance (parent edges)
// composed with group membership (team:eng) — ReBAC's distinctive character over RBAC/ACL.
public static class RebacSeeder
{
    public const string StoreName = "authn-authz";

    public static readonly IReadOnlyList<RebacTuple> Tuples =
    [
        new("prefix:projects/",        "parent", "prefix:projects/apollo/"),        // hierarchy edge
        new("prefix:projects/apollo/", "parent", "prefix:projects/apollo/specs/"),  // hierarchy edge
        new("user:bob",                "member", "team:eng"),                        // group membership
        new("user:erin",               "member", "team:eng"),                        // group membership
        new("team:eng#member",         "editor", "prefix:projects/"),               // group × inheritance
        new("user:carol",              "viewer", "prefix:projects/"),               // inherited read
        new("user:alice",              "owner",  "prefix:projects/apollo/"),        // owner ⇒ editor
        new("user:*",                  "viewer", "prefix:shared/"),                  // public read
    ];

    // Every prefix object that appears anywhere in the seeded graph (either side of a tuple).
    // A resource whose containing prefix falls outside this set was never wired into the graph —
    // its Check() result is a coverage gap, not a policy decision. See RebacEvaluator.
    public static readonly IReadOnlySet<string> ModeledPrefixes = Tuples
        .SelectMany(t => new[] { t.User, t.Object })
        .Where(s => s.StartsWith("prefix:", StringComparison.Ordinal))
        .ToHashSet();
}
