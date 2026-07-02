"use client";

import { useState } from "react";
import { useAuth } from "react-oidc-context";
import { apiUrl } from "@/auth/oidc";

type WhoAmI = { subject: string; name: string; roles: string[] };
type Roundtrip = WhoAmI & {
  roleArn: string;
  objectKey: string;
  contentMatched: boolean;
};

export default function Home() {
  const auth = useAuth();
  const [whoami, setWhoami] = useState<WhoAmI | null>(null);
  const [roundtrip, setRoundtrip] = useState<Roundtrip | null>(null);
  const [error, setError] = useState("");

  if (auth.isLoading) return <main style={main}>Loading…</main>;

  if (!auth.isAuthenticated) {
    return (
      <main style={main}>
        <h1>authn-authz walking skeleton</h1>
        {auth.error && <pre style={errBox}>{auth.error.message}</pre>}
        <button style={btn} onClick={() => void auth.signinRedirect()}>
          Sign in with Keycloak
        </button>
      </main>
    );
  }

  const access = auth.user?.access_token ?? "";
  const idToken = auth.user?.id_token ?? "";

  async function call<T>(path: string, init: RequestInit, set: (v: T) => void) {
    setError("");
    const res = await fetch(`${apiUrl}${path}`, init);
    if (!res.ok) {
      setError(`${path} → HTTP ${res.status}`);
      return;
    }
    set((await res.json()) as T);
  }

  return (
    <main style={main}>
      <h1>authn-authz walking skeleton</h1>
      <p>
        Signed in as <b>{auth.user?.profile.preferred_username}</b>
      </p>
      <div style={row}>
        <button
          style={btn}
          onClick={() =>
            call<WhoAmI>("/whoami", { headers: { Authorization: `Bearer ${access}` } }, setWhoami)
          }
        >
          GET /whoami
        </button>
        <button
          style={btn}
          onClick={() =>
            call<Roundtrip>(
              "/storage/roundtrip",
              { method: "POST", headers: { Authorization: `Bearer ${access}`, "X-Id-Token": idToken } },
              setRoundtrip,
            )
          }
        >
          POST /storage/roundtrip
        </button>
        <button style={btnGhost} onClick={() => void auth.removeUser()}>
          Sign out
        </button>
      </div>

      {error && <pre style={errBox}>{error}</pre>}
      {whoami && (
        <section>
          <h3>/whoami</h3>
          <pre style={box}>{JSON.stringify(whoami, null, 2)}</pre>
        </section>
      )}
      {roundtrip && (
        <section>
          <h3>/storage/roundtrip</h3>
          <pre style={box}>{JSON.stringify(roundtrip, null, 2)}</pre>
        </section>
      )}
    </main>
  );
}

const main: React.CSSProperties = {
  padding: 32,
  maxWidth: 720,
  margin: "0 auto",
  fontFamily: "system-ui, sans-serif",
};
const row: React.CSSProperties = { display: "flex", gap: 12, margin: "16px 0" };
const btn: React.CSSProperties = {
  padding: "8px 16px",
  border: "none",
  borderRadius: 6,
  background: "#5b5bd6",
  color: "white",
  cursor: "pointer",
};
const btnGhost: React.CSSProperties = { ...btn, background: "#444" };
const box: React.CSSProperties = {
  background: "#1e1e2e",
  color: "#cdd6f4",
  padding: 16,
  borderRadius: 6,
  overflowX: "auto",
};
const errBox: React.CSSProperties = { ...box, background: "#3a1e1e", color: "#f4cdcd" };
