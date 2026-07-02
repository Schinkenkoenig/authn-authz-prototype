"""Refresher sidecar: the IRSA/Pod-Identity stand-in for local dev.

Periodically fetches a client-credentials token for the `storage-service` Keycloak
client and writes it (atomically) to a shared token file. The API never fetches its
own identity token — it only reads AWS_WEB_IDENTITY_TOKEN_FILE, exactly as a pod reads
a projected service-account token. The AWS SDK's web-identity provider re-reads this
file when it refreshes credentials.
"""
import json
import os
import time
import urllib.parse
import urllib.request

KC = os.environ["KC"]
OUT = os.environ["OUT"]
SECRET = os.environ["SECRET"]
CLIENT = os.environ.get("CLIENT", "storage-service")
INTERVAL = int(os.environ.get("INTERVAL", "120"))
TOKEN_URL = f"{KC}/realms/authn-authz/protocol/openid-connect/token"


def refresh() -> None:
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": CLIENT,
        "client_secret": SECRET,
    }).encode()
    with urllib.request.urlopen(TOKEN_URL, data=data) as resp:
        token = json.load(resp)["access_token"]
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        f.write(token)
    os.replace(tmp, OUT)  # atomic — the API never sees a partial write


if __name__ == "__main__":
    while True:
        try:
            refresh()
            print("token refreshed", flush=True)
        except Exception as e:  # keep the loop alive across Keycloak restarts
            print(f"refresh error: {e}", flush=True)
        time.sleep(INTERVAL)
