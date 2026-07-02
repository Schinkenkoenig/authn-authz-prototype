"use client";

import { useAuth } from "react-oidc-context";

// react-oidc-context processes the code exchange automatically on mount (the redirect
// URI lands here); onSigninCallback then sends us home. This page is just the interim.
export default function Callback() {
  const auth = useAuth();
  return (
    <main style={{ padding: 24, fontFamily: "sans-serif" }}>
      {auth.error ? `Login failed: ${auth.error.message}` : "Signing in…"}
    </main>
  );
}
