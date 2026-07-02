namespace Api.Storage;

// Where Ceph RGW lives and which bucket the walking skeleton uses. Bound from the
// "Ceph" configuration section; injected by Aspire in the orchestrated topology and
// supplied via appsettings for the standalone spike verify.
public sealed class CephSettings
{
    public string ServiceUrl { get; init; } = "";
    public string Region { get; init; } = "us-east-1";
    public string Bucket { get; init; } = "demo";
}
