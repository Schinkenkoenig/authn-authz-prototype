using Api.Auth;

namespace Api.Authz;

// Claim-based: the IdP issues the grants in the token and the app trusts them. There is NO app
// config — the admin surface is the Keycloak claim mapper. Grants look like "r:finance/",
// "rw:projects/apollo/", "rw:*". Contrast: revocation waits for token expiry.
public static class ClaimsEvaluator
{
    public static AuthzDecision Evaluate(CallerClaims caller, StorageAction action, string resource)
    {
        foreach (var grant in caller.StorageGrants)
        {
            var colon = grant.IndexOf(':');
            if (colon < 0) continue;
            var caps = grant[..colon];
            var prefix = grant[(colon + 1)..];
            if (!Allows(caps, action)) continue;
            if (PrefixMatch.Covers(prefix, resource))
                return new(true, $"token grant '{grant}' permits {action}", "claims");
        }
        return new(false, $"no token grant permits {action} on '{resource}'", "claims");
    }

    static bool Allows(string caps, StorageAction action) => action switch
    {
        StorageAction.Write => caps.Contains('w'),
        StorageAction.Read => caps.Contains('r'),
        StorageAction.List => caps.Contains('r'), // read implies list
        _ => false,
    };
}
