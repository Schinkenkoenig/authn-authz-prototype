using Api.Authz;

namespace Api.Tests;

public class PrefixMatchTests
{
    [Theory]
    [InlineData("finance/", "finance/q1.txt", true)]      // under the prefix
    [InlineData("finance/", "finance/2026/q1.txt", true)] // nested
    [InlineData("finance/", "finance", false)]            // the bare prefix name is not "under" it
    [InlineData("finance/", "engineering/x", false)]      // different prefix
    [InlineData("finance/", "financials/x", false)]       // not fooled by shared leading text
    [InlineData("finance/q1.txt", "finance/q1.txt", true)]// exact key grant
    [InlineData("*", "anything/at/all", true)]            // wildcard grants everything
    [InlineData("", "/x", false)]                         // empty grant covers nothing (not "/")
    [InlineData("", "x", false)]                          // empty grant covers nothing
    public void Covers(string grant, string resource, bool expected) =>
        Assert.Equal(expected, PrefixMatch.Covers(grant, resource));
}
