namespace Api.Authz;

// The single resource-coverage rule shared by every prefix-granting paradigm, so decisions
// differ because of config shape — not matching quirks. A grant covers a resource when it is
// "*" (all), an exact key match, or a directory prefix the resource sits strictly under.
public static class PrefixMatch
{
    public static bool Covers(string grant, string resource)
    {
        if (grant == "*") return true;
        if (grant == resource) return true;
        var prefix = grant.EndsWith('/') ? grant : grant + "/";
        return resource.StartsWith(prefix, StringComparison.Ordinal);
    }
}
