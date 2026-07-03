using Api.Auth;
using Api.Authz;
using FastEndpoints;

namespace Api.Endpoints;

// Exposes the admin's config artifact for a paradigm — the "burden" the showcase points at. The
// three DB-backed paradigms return their seeded config; claim-based returns a pointer to Keycloak
// plus the caller's live grant claim, because its config lives in the IdP, not our DB.
public sealed class AuthzConfigEndpoint(AuthzConfigStore store) : EndpointWithoutRequest<object>
{
    public override void Configure()
    {
        Get("/authz/{paradigm}/config");
        Policies("authenticated");
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var paradigm = Route<string>("paradigm") ?? "";
        object? body = paradigm switch
        {
            "rbac" => store.Current.Rbac,
            "abac" => store.Current.Abac,
            "acl" => store.Current.Acl,
            "claims" => new
            {
                source = "keycloak",
                note = "config lives in the IdP claim mapper; the app trusts the token",
                callerGrants = CallerClaims.FromPrincipal(User).StorageGrants,
            },
            "rebac" => new
            {
                engine = "openfga",
                note = "config is a relationship graph in OpenFGA: the model is the schema, the tuples are the data",
                model = RebacModel.Dsl,
                tuples = RebacSeeder.Tuples,
            },
            "opa" => new
            {
                engine = "opa",
                note = "config is a Rego module evaluated over a per-request input document",
                rego = PolicyAssets.Rego,
            },
            "cedar" => new
            {
                engine = "cedar",
                note = "config is a set of Cedar permit/forbid policies; decision data rides in context",
                policies = System.Text.Json.JsonDocument.Parse(PolicyAssets.CedarPolicies).RootElement,
            },
            _ => null,
        };

        if (body is null)
        {
            await Send.NotFoundAsync(ct);
            return;
        }

        await Send.OkAsync(body, ct);
    }
}
