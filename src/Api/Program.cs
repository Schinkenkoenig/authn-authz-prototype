using Api.Data;
using Api.Storage;
using FastEndpoints;
using FastEndpoints.Swagger;
using Microsoft.EntityFrameworkCore;
using OpenTelemetry.Trace;
using Scalar.AspNetCore;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Drop the default console provider so Serilog owns stdout; AddServiceDefaults re-adds the
// OpenTelemetry logging provider below (which exports to the Aspire dashboard).
builder.Logging.ClearProviders();

builder.AddServiceDefaults();

// Serilog structured logging: pretty console for local, and (writeToProviders) forwarded to
// the MEL pipeline so ServiceDefaults' OpenTelemetry logging exports it to the Aspire dashboard.
builder.Services.AddSerilog((_, cfg) => cfg
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console(), writeToProviders: true);

// Make the AWS SDK calls (STS AssumeRoleWithWebIdentity + S3 PUT/GET) first-class spans so
// one trace covers request → STS → S3.
builder.Services.ConfigureOpenTelemetryTracerProvider(t => t.AddAWSInstrumentation());

// Access token (aud=api) authorizes API calls. Realm roles stay nested under the raw
// `realm_access` claim, so keep raw JWT claim names (MapInboundClaims=false); http
// issuer in dev (RequireHttpsMetadata=false).
builder.Services
    .AddAuthentication()
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["Oidc:Authority"];
        options.Audience = builder.Configuration["Oidc:Audience"] ?? "api";
        options.RequireHttpsMetadata = false;
        options.MapInboundClaims = false;
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("authenticated", p => p.RequireAuthenticatedUser());

// The SPA is a separate origin; it sends the access token (Authorization). Origins come
// from config so the orchestrated topology can override the dev default.
var spaOrigins = builder.Configuration.GetSection("Cors:Origins").Get<string[]>()
    ?? ["http://localhost:3000"];
builder.Services.AddCors(o => o.AddPolicy("spa", p => p
    .WithOrigins(spaOrigins)
    .WithHeaders("Authorization", "Content-Type")
    .WithMethods("GET", "POST")));

builder.Services.AddFastEndpoints();
builder.Services.SwaggerDocument();

var ceph = builder.Configuration.GetSection("Ceph").Get<CephSettings>() ?? new CephSettings();
builder.Services.AddSingleton(ceph);
builder.Services.AddSingleton<S3Gateway>();
builder.Services.AddSingleton<Api.Authz.AuthzConfigStore>();

// External authorization engines: each provisioned at startup like the DB migrate→seed (fail-fast
// if configured but unreachable). When a URL is unset, a deny stand-in keeps the other paradigms
// working. All are registered as IExternalEvaluator and dispatched by paradigm name.
var openfgaUrl = builder.Configuration["Openfga:ApiUrl"];
builder.Services.AddSingleton<Api.Authz.IExternalEvaluator>(string.IsNullOrEmpty(openfgaUrl)
    ? new Api.Authz.UnconfiguredEvaluator("rebac")
    : new Api.Authz.RebacExternalEvaluator(new Api.Authz.OpenFgaRebacClient(
        await Api.Authz.RebacProvisioner.ProvisionAsync(openfgaUrl, Api.Authz.RebacModel.Json, CancellationToken.None))));

var cedarUrl = builder.Configuration["Cedar:ApiUrl"];
builder.Services.AddSingleton<Api.Authz.IExternalEvaluator>(string.IsNullOrEmpty(cedarUrl)
    ? new Api.Authz.UnconfiguredEvaluator("cedar")
    : new Api.Authz.CedarEvaluator(await Api.Authz.CedarProvisioner.ProvisionAsync(
        cedarUrl, Api.Authz.PolicyAssets.CedarPolicies, Api.Authz.PolicyAssets.CedarEntities, CancellationToken.None)));

var opaUrl = builder.Configuration["Opa:ApiUrl"];
builder.Services.AddSingleton<Api.Authz.IExternalEvaluator>(string.IsNullOrEmpty(opaUrl)
    ? new Api.Authz.UnconfiguredEvaluator("opa")
    : new Api.Authz.OpaEvaluator(
        await Api.Authz.OpaProvisioner.ProvisionAsync(opaUrl, Api.Authz.PolicyAssets.Rego, CancellationToken.None)));

builder.Services.AddSingleton<IReadOnlyDictionary<string, Api.Authz.IExternalEvaluator>>(sp =>
    sp.GetServices<Api.Authz.IExternalEvaluator>().ToDictionary(e => e.Paradigm));

builder.Services.AddDbContext<AppDbContext>(o =>
    o.UseNpgsql(builder.Configuration.GetConnectionString("appdb")));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate();
    Api.Authz.AuthzSeeder.Seed(db);
    app.Services.GetRequiredService<Api.Authz.AuthzConfigStore>().Load(db);
}

app.UseSerilogRequestLogging();
app.UseCors("spa");
app.UseAuthentication();
app.UseAuthorization();
app.UseFastEndpoints();
app.UseSwaggerGen();
app.MapScalarApiReference(o => o.WithOpenApiRoutePattern("/swagger/{documentName}/swagger.json"));

app.MapDefaultEndpoints();

app.Run();
