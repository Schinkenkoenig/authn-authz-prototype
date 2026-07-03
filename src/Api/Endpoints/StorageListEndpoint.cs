using Api.Auth;
using Api.Authz;
using Api.Storage;
using FastEndpoints;

namespace Api.Endpoints;

// GET has no body — FastEndpoints instantiates this and binds from the query string, which needs
// a settable property (NOT an init-only positional record, which fails to bind at runtime).
public sealed class ListRequest { public string Prefix { get; set; } = ""; }

public sealed record ListResult(string Paradigm, bool Permit, string Reason, string Prefix, IReadOnlyList<string> Keys);

public sealed class StorageListEndpoint(AuthzConfigStore store, S3Gateway s3, IRebacClient rebac)
    : Endpoint<ListRequest, ListResult>
{
    public override void Configure()
    {
        Get("/storage/list");
        Policies("authenticated");
    }

    public override async Task HandleAsync(ListRequest req, CancellationToken ct)
    {
        var caller = CallerClaims.FromPrincipal(User);
        var paradigm = AuthzDispatcher.Resolve(HttpContext.Request.Headers["X-Authz-Paradigm"].ToString());
        var decision = await AuthzDispatcher.DecideAsync(paradigm, new AuthzRequest(caller, StorageAction.List, req.Prefix), store.Current, rebac, ct);

        if (!decision.Permit)
        {
            await Send.ResponseAsync(new ListResult(paradigm, false, decision.Reason, req.Prefix, []), 403, ct);
            return;
        }

        var keys = await s3.ListAsync(req.Prefix, ct);
        await Send.OkAsync(new ListResult(paradigm, true, decision.Reason, req.Prefix, keys), ct);
    }
}
