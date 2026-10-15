# PocketShell MCP

Remote MCP tools for PocketShell and DataOps. Assistant computers need no saved CLI login, SSH key or host pins. A persistent service holds that state and connects through the existing PocketShell gateway.

The server uses standard Streamable HTTP and MCP OAuth: discovery, dynamic client registration, authorization code with S256 PKCE, audience binding, short access tokens and rotating refresh tokens. It has no ChatGPT-specific transport or token exchange. The same endpoint can be connected by ChatGPT/dots, Claude, Grok Bot, Cursor, Codex and other OAuth-capable MCP clients.

**Status:** protocol tests and Inspector HTTPS tests pass. Production installation and actual ChatGPT/dots, Claude and Grok Bot account tests remain required. Protocol compatibility is not a claim that those account tests have passed.

## Tools

| Service | Tools |
| --- | --- |
| PocketShell | `hosts`, `ls`, `start`, `send`, `capture`, `stop`, `status` |
| DataOps | `dataops_guide`, `dataops_read`, `dataops_write` |

PocketShell operations invoke the same `psc` runtime used by the terminal client. Account/device/gateway functions come from `@pocketshell/tui-client/core`. The public entry point lives in the upstream client package; it re-exports the existing implementations. The lower-level host contract remains in `@pocketshell/core`. The build pins both upstream source revisions. Generated bundles stay outside Git because upstream defaults can contain deployment details.

DataOps tools access the same portal API as `dataops api`. They preserve portal permissions, JSON bodies and query parameters. Auth/token-management endpoints and local filesystem access are excluded. Binary uploads/downloads use the portal.

## Development

Requires Node 24, npm, Git and OpenSSL for the HTTPS tests. SSH operations also require OpenSSH.

```sh
npm ci
npm test
node scripts/build-client.mjs
```

The build downloads pinned public client/core sources into a temporary directory, compiles the shared code, and removes the sources. To use an existing checkout, pass its path as the first argument.

Configure a service using the variables in [configuration](docs/configuration.md), then run `npm start`. Run PocketShell and DataOps as separate service users with separate state directories, storage keys and issuer URLs. Infrastructure belongs in the infrastructure repository; this repository does not create AWS resources.

See [connection steps](docs/connecting.md) for ChatGPT/dots, Claude, Grok Bot, Cursor, Codex and Inspector. [Security and limits](docs/security.md) describes credential storage, host trust and operating limits.
