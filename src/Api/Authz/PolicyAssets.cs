namespace Api.Authz;

// Policy artifacts copied next to the assembly at build (see Api.csproj). The Rego module and the
// Cedar policy/entity JSON are the source of truth, pushed to the engines at startup and surfaced
// by /authz/{opa,cedar}/config.
public static class PolicyAssets
{
    static readonly string Dir = Path.Combine(AppContext.BaseDirectory, "Authz", "policy");

    public static string Rego => File.ReadAllText(Path.Combine(Dir, "authz.rego"));
    public static string CedarPolicies => File.ReadAllText(Path.Combine(Dir, "cedar-policies.json"));
    public static string CedarEntities => File.ReadAllText(Path.Combine(Dir, "cedar-entities.json"));
}
