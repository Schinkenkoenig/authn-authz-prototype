"use client";

import { AuthProvider } from "react-oidc-context";
import { oidcConfig } from "@/auth/oidc";

export function Providers({ children }: { children: React.ReactNode }) {
  return <AuthProvider {...oidcConfig}>{children}</AuthProvider>;
}
