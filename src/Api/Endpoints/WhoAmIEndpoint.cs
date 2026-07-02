using Api.Auth;
using FastEndpoints;

namespace Api.Endpoints;

// Reflects back the identity the API validated from the access token (aud=api).
// Thin shell over CallerClaims; the extraction logic is unit-tested.
public sealed class WhoAmIEndpoint : EndpointWithoutRequest<CallerClaims>
{
    public override void Configure()
    {
        Get("/whoami");
        Policies("authenticated");
    }

    public override async Task HandleAsync(CancellationToken ct) =>
        await Send.OkAsync(CallerClaims.FromPrincipal(User), ct);
}
