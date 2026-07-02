using Api.Data;
using Api.Storage;
using FastEndpoints;
using FastEndpoints.Swagger;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

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

// The SPA is a separate origin; it sends the access token (Authorization) and the
// ID token (X-Id-Token). Origins come from config so the orchestrated topology can
// override the dev default.
var spaOrigins = builder.Configuration.GetSection("Cors:Origins").Get<string[]>()
    ?? ["http://localhost:3000"];
builder.Services.AddCors(o => o.AddPolicy("spa", p => p
    .WithOrigins(spaOrigins)
    .WithHeaders("Authorization", "X-Id-Token", "Content-Type")
    .WithMethods("GET", "POST")));

builder.Services.AddFastEndpoints();
builder.Services.SwaggerDocument();

var ceph = builder.Configuration.GetSection("Ceph").Get<CephSettings>() ?? new CephSettings();
builder.Services.AddSingleton(ceph);
builder.Services.AddSingleton<StsBroker>();
builder.Services.AddSingleton<S3Gateway>();

builder.Services.AddDbContext<AppDbContext>(o =>
    o.UseNpgsql(builder.Configuration.GetConnectionString("appdb")));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.Migrate();
}

app.UseCors("spa");
app.UseAuthentication();
app.UseAuthorization();
app.UseFastEndpoints();
app.UseSwaggerGen();
app.MapScalarApiReference(o => o.WithOpenApiRoutePattern("/swagger/{documentName}/swagger.json"));

app.MapDefaultEndpoints();

app.Run();
