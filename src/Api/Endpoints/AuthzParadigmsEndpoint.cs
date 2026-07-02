using Api.Authz;
using FastEndpoints;

namespace Api.Endpoints;

public sealed class AuthzParadigmsEndpoint : EndpointWithoutRequest<IReadOnlyList<string>>
{
    public override void Configure()
    {
        Get("/authz/paradigms");
        Policies("authenticated");
    }

    public override async Task HandleAsync(CancellationToken ct) =>
        await Send.OkAsync(AuthzDispatcher.Paradigms, ct);
}
