namespace Api.Authz;

// The ReBAC authorization model artifacts, copied next to the assembly at build (see Api.csproj).
// The DSL is the human-readable source of truth (shown by /authz/rebac/config); the JSON is the
// transformed form OpenFGA loads (produced by `fga model transform`, committed alongside the DSL).
public static class RebacModel
{
    static readonly string Dir = Path.Combine(AppContext.BaseDirectory, "Authz", "rebac");

    public static string Dsl => File.ReadAllText(Path.Combine(Dir, "model.fga"));
    public static string Json => File.ReadAllText(Path.Combine(Dir, "model.json"));
}
