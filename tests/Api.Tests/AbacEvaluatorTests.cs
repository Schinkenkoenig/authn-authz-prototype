using Api.Auth;
using Api.Authz;

namespace Api.Tests;

public class AbacEvaluatorTests
{
    static CallerClaims User(string dept, string level) =>
        new("sub", "u", [], new Dictionary<string, string> { ["department"] = dept, ["level"] = level }, []);

    // Rule 1: anyone may read+write under their own department prefix (templated).
    // Rule 2: level >= 3 may read hr/.
    static readonly AbacConfig Config = new(
    [
        new AbacRule([], "{department}/", [StorageAction.Read, StorageAction.Write]),
        new AbacRule([new AttrPredicate("level", "gte", "3")], "hr/", [StorageAction.Read]),
    ]);

    [Fact]
    public void Department_template_grants_own_prefix()
    {
        var d = AbacEvaluator.Evaluate(User("finance", "2"), StorageAction.Write, "finance/q1.txt", Config);
        Assert.True(d.Permit);
    }

    [Fact]
    public void Department_template_denies_other_prefix()
    {
        var d = AbacEvaluator.Evaluate(User("finance", "2"), StorageAction.Write, "engineering/x", Config);
        Assert.False(d.Permit);
    }

    [Fact]
    public void Level_condition_gates_hr_read()
    {
        Assert.True(AbacEvaluator.Evaluate(User("engineering", "3"), StorageAction.Read, "hr/records.txt", Config).Permit);
        Assert.False(AbacEvaluator.Evaluate(User("engineering", "2"), StorageAction.Read, "hr/records.txt", Config).Permit);
    }
}
