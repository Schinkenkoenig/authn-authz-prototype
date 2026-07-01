var builder = DistributedApplication.CreateBuilder(args);

// Keycloak: OIDC provider. Realm (clients, mappers, roles, users) is imported
// from committed source on first start.
var keycloak = builder.AddKeycloak("keycloak")
    .WithDataVolume()
    .WithRealmImport("./realms");

// Postgres: application database. One trivial table proves the wiring (see Api).
var postgres = builder.AddPostgres("postgres")
    .WithDataVolume();
var appdb = postgres.AddDatabase("appdb");

builder.Build().Run();
