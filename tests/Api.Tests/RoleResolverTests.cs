using Api.Authz;

namespace Api.Tests;

public class RoleResolverTests
{
    [Fact]
    public void Writer_can_write()
    {
        Assert.True(RoleResolver.CanWrite(new[] { "writer" }));
    }

    [Fact]
    public void Reader_cannot_write()
    {
        Assert.False(RoleResolver.CanWrite(new[] { "reader" }));
    }

    [Fact]
    public void Reader_and_writer_can_write()
    {
        Assert.True(RoleResolver.CanWrite(new[] { "reader", "writer" }));
    }
}
