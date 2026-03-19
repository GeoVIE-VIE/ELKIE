#!/usr/bin/env python3
"""One-time OAuth device code flow to get Microsoft Graph tokens for Outlook Sentinel."""

import json
import msal

CLIENT_ID = "49d62aab-a482-4485-a5cb-9af0a33d250e"
TENANT_ID = "47249bf2-ad9d-4081-8b22-048eb52339b6"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["Mail.Read", "Mail.ReadWrite"]
TOKEN_CACHE_FILE = "/home/legs/.outlook_token_cache.json"

def main():
    # Load existing cache
    cache = msal.SerializableTokenCache()
    try:
        with open(TOKEN_CACHE_FILE) as f:
            cache.deserialize(f.read())
    except FileNotFoundError:
        pass

    app = msal.PublicClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        token_cache=cache,
    )

    # Check for existing accounts
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
        if result and "access_token" in result:
            print(f"Already authenticated as {accounts[0]['username']}")
            print(f"Token valid — you're good to go.")
            return

    # Device code flow
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        print(f"Error: {flow.get('error_description', flow)}")
        return

    print(flow["message"])
    print("\nWaiting for you to complete authentication...")

    result = app.acquire_token_by_device_flow(flow)

    if "access_token" in result:
        print(f"\nAuthenticated as {result.get('id_token_claims', {}).get('preferred_username', 'unknown')}")
        print("Token cached — Outlook Sentinel can now access your mailbox.")

        # Save cache
        with open(TOKEN_CACHE_FILE, "w") as f:
            f.write(cache.serialize())

        import os
        os.chmod(TOKEN_CACHE_FILE, 0o600)
    else:
        print(f"\nAuth failed: {result.get('error_description', result)}")

if __name__ == "__main__":
    main()
