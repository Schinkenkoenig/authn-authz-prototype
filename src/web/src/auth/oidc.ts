import type { AuthProviderProps } from "react-oidc-context";

// Public client config (Auth Code + PKCE). Authority/client_id/api are not secrets;
// dev defaults point at the fixed-IP spike Keycloak so the browser, API, and Ceph all
// agree on one issuer (see dev-up.sh). Override via NEXT_PUBLIC_* in other topologies.
const authority =
  process.env.NEXT_PUBLIC_OIDC_AUTHORITY ??
  "http://172.30.0.20:8080/realms/authn-authz";

export const clientId = process.env.NEXT_PUBLIC_OIDC_CLIENT_ID ?? "webapp";
export const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5080";

const origin =
  typeof window !== "undefined" ? window.location.origin : "http://localhost:3000";

export const oidcConfig: AuthProviderProps = {
  authority,
  client_id: clientId,
  redirect_uri: `${origin}/callback`,
  post_logout_redirect_uri: origin,
  response_type: "code",
  scope: "openid profile",
  // Land back on the home page with a clean URL once the code exchange completes.
  onSigninCallback: () => window.location.replace("/"),
};
