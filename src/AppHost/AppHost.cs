var builder = DistributedApplication.CreateBuilder(args);

// App-tier orchestration. Keycloak, Ceph, and the web-identity refresher stay as fixed-IP
// infra in scripts/dev-up.sh: they need one issuer string reachable identically from the
// browser, the API, and Ceph, which a fixed bridge IP satisfies but Aspire's networking
// fights (see docs .../authz-pivot-service-iam + the STS verdicts note). The API here runs
// as a host process, so it reaches those fixed IPs directly.

var postgres = builder.AddPostgres("postgres").WithDataVolume();
var appdb = postgres.AddDatabase("appdb");

const string issuer = "http://172.30.0.20:8080/realms/authn-authz";
const string cephUrl = "http://172.30.0.10:8080";
const string openfgaUrl = "http://172.30.0.30:8080";
const string opaUrl = "http://172.30.0.50:8181";

var api = builder.AddProject<Projects.Api>("api")
    .WithReference(appdb)
    .WaitFor(appdb)
    .WithEnvironment("Oidc__Authority", issuer)
    .WithEnvironment("Oidc__Audience", "api")
    .WithEnvironment("Ceph__ServiceUrl", cephUrl)
    .WithEnvironment("Openfga__ApiUrl", openfgaUrl)
    .WithEnvironment("Opa__ApiUrl", opaUrl)
    .WithEnvironment("Ceph__Region", "us-east-1")
    .WithEnvironment("Ceph__Bucket", "demo")
    .WithEnvironment("Cors__Origins__0", "http://localhost:3000")
    // Storage credentials via the AWS SDK web-identity provider (service identity). The token
    // file is kept fresh by the dev-up refresher sidecar; the API only reads it.
    .WithEnvironment("AWS_ROLE_ARN", "arn:aws:iam:::role/DemoService")
    .WithEnvironment("AWS_WEB_IDENTITY_TOKEN_FILE", "/tmp/webid/token")
    .WithEnvironment("AWS_ROLE_SESSION_NAME", "storage-service")
    .WithEnvironment("AWS_REGION", "us-east-1")
    .WithEnvironment("AWS_DEFAULT_REGION", "us-east-1")
    .WithEnvironment("AWS_ENDPOINT_URL_STS", cephUrl);

builder.AddNpmApp("web", "../web", "dev")
    .WithReference(api)
    .WaitFor(api)
    .WithHttpEndpoint(env: "PORT", port: 3000)
    .WithEnvironment("NEXT_PUBLIC_API_URL", api.GetEndpoint("http"))
    .WithEnvironment("NEXT_PUBLIC_OIDC_AUTHORITY", issuer)
    .WithEnvironment("NEXT_PUBLIC_OIDC_CLIENT_ID", "webapp");

builder.Build().Run();
