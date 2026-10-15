# Service configuration

All examples are placeholders. Supply deployment addresses and account information through private runtime configuration.

| Variable | Meaning |
| --- | --- |
| `MCP_SERVICE` | `pocketshell` or `dataops` |
| `MCP_ISSUER` | Public HTTPS origin, optionally followed by a single service path; no trailing slash |
| `MCP_UPSTREAM_ORIGIN` | PocketShell broker origin or DataOps portal origin |
| `MCP_WEB_ORIGIN` | Trusted device-approval web origin |
| `MCP_GATEWAY_ORIGIN` | PocketShell gateway HTTPS origin; PocketShell only |
| `MCP_ALLOWED_EMAILS` | Required comma-separated allowlist of upstream-verified account emails |
| `MCP_REDIRECT_URIS` | Optional exact callback allowlist; unset accepts standard HTTPS and HTTP-loopback DCR callbacks |
| `MCP_STORAGE_KEY_FILE` | Preferred: path to a protected file containing a 32-byte hexadecimal encryption key |
| `MCP_STORAGE_KEY` | Alternative hexadecimal storage key supplied by the secret manager |
| `MCP_STATE_DIR` | Private mode-0700 persistent directory for encrypted SQLite state |
| `MCP_BIND`, `PORT` | Private listening address and port; defaults to loopback and port 8080 |

For example, use `https://mcp.example.com` for PocketShell and `https://mcp.example.com/dataops` for DataOps. Their MCP resources are `/mcp` and `/dataops/mcp`. The server advertises the correct discovery addresses for either path.

No service address, account email, SSH identity or host pin is built into the public project. Preserve the storage key when updating configuration. Back up the encrypted store and its key through the managed secret and backup systems; losing the key loses access to stored grants and SSH profiles.

## PocketShell SSH profile

A human administrator provisions a profile after verifying host keys independently and enrolling an SSH client public key using PocketShell's normal host setup. The profile is JSON supplied on stdin:

```json
{
  "hosts": [{"name": "example-host", "deviceId": "example-device", "user": "example-user"}],
  "privateKey": "<dedicated SSH private key from secure storage>",
  "pins": "<complete known_hosts lines verified independently on each host>"
}
```

Run `node scripts/provision-profile.mjs <account-email>` as the service user with the same state directory and storage-key credential, redirecting the private JSON file into stdin. Do not use an argument for secret content. The profile is encrypted in the state database. This is administrator provisioning, not a connector user's login step.

The assistant has no profile-editing, pin-replacement, arbitrary SSH destination, local-host or local-file tool. Gateway discovery only reports devices; an advertised host key never becomes a trusted pin.
