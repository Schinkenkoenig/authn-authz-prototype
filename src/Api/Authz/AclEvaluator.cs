using Api.Auth;

namespace Api.Authz;

// ACL: each prefix carries an explicit who-can-do-what list; "*" principal means everyone. The
// dumb baseline — obvious for small ad-hoc sharing, but grows linearly and offers no reuse.
public sealed record AclEntry(string Prefix, string Principal, IReadOnlyList<StorageAction> Actions);

public sealed record AclConfig(IReadOnlyList<AclEntry> Entries);

public static class AclEvaluator
{
    public static AuthzDecision Evaluate(CallerClaims caller, StorageAction action, string resource, AclConfig cfg)
    {
        foreach (var e in cfg.Entries)
        {
            if (e.Principal != "*" && e.Principal != caller.Name) continue;
            if (!e.Actions.Contains(action)) continue;
            if (PrefixMatch.Covers(e.Prefix, resource))
                return new(true, $"ACL on '{e.Prefix}' grants {action} to '{e.Principal}'", "acl");
        }
        return new(false, $"no ACL entry grants {action} on '{resource}' to '{caller.Name}'", "acl");
    }
}
