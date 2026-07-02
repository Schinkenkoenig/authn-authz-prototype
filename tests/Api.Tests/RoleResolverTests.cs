using Api.Authz;

namespace Api.Tests;

public class RoleResolverTests
{
    [Fact]
    public void Reader_role_maps_to_reader_arn()
    {
        var arn = RoleResolver.ResolveRoleArn(new[] { "reader" });
        Assert.Equal("arn:aws:iam:::role/DemoReader", arn);
    }

    [Fact]
    public void Writer_role_wins_over_reader()
    {
        var arn = RoleResolver.ResolveRoleArn(new[] { "reader", "writer" });
        Assert.Equal("arn:aws:iam:::role/DemoWriter", arn);
    }

    [Fact]
    public void No_known_role_throws() =>
        Assert.Throws<UnauthorizedAccessException>(() => RoleResolver.ResolveRoleArn(new[] { "guest" }));
}
