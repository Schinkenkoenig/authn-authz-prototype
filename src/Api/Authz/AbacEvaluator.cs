using Api.Auth;

namespace Api.Authz;

// ABAC derives access from caller attributes. A rule applies when all its conditions hold and its
// prefix template (which may reference attributes, e.g. "{department}/") resolves. Sweet spot:
// onboarding needs zero authz change — a new finance user is covered by the department rule.
public sealed record AttrPredicate(string Attribute, string Op, string Value); // Op: "eq" | "gte"

public sealed record AbacRule(
    IReadOnlyList<AttrPredicate> Conditions,
    string PrefixTemplate,
    IReadOnlyList<StorageAction> Actions);

public sealed record AbacConfig(IReadOnlyList<AbacRule> Rules);

public static class AbacEvaluator
{
    public static AuthzDecision Evaluate(CallerClaims caller, StorageAction action, string resource, AbacConfig cfg)
    {
        foreach (var rule in cfg.Rules)
        {
            if (!rule.Actions.Contains(action)) continue;
            if (!rule.Conditions.All(c => Holds(c, caller.Attributes))) continue;
            if (!TryResolve(rule.PrefixTemplate, caller.Attributes, out var prefix)) continue;
            if (PrefixMatch.Covers(prefix, resource))
                return new(true, $"attributes satisfy rule → {action} on '{prefix}'", "abac");
        }
        return new(false, $"no attribute rule grants {action} on '{resource}'", "abac");
    }

    static bool Holds(AttrPredicate p, IReadOnlyDictionary<string, string> attrs)
    {
        if (!attrs.TryGetValue(p.Attribute, out var value)) return false;
        return p.Op switch
        {
            "eq" => value == p.Value,
            "gte" => int.TryParse(value, out var v) && int.TryParse(p.Value, out var t) && v >= t,
            _ => false,
        };
    }

    // Substitute {attr} placeholders from caller attributes. A referenced attribute that is
    // missing means the rule does not apply to this caller.
    static bool TryResolve(string template, IReadOnlyDictionary<string, string> attrs, out string resolved)
    {
        resolved = template;
        var open = resolved.IndexOf('{');
        while (open >= 0)
        {
            var close = resolved.IndexOf('}', open);
            if (close < 0) break;
            var name = resolved[(open + 1)..close];
            // A missing OR empty attribute means the rule does not apply — otherwise a blank
            // attribute would collapse "{attr}/" to "/" and match everything.
            if (!attrs.TryGetValue(name, out var value) || string.IsNullOrEmpty(value)) { resolved = ""; return false; }
            resolved = resolved[..open] + value + resolved[(close + 1)..];
            open = resolved.IndexOf('{');
        }
        return true;
    }
}
