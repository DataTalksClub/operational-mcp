# Add a connector

Use the deployed public HTTPS URL supplied by the operator. The examples below use `https://mcp.example.com/mcp`; use `https://mcp.example.com/dataops/mcp` for DataOps. The URL must be reachable from the assistant provider's servers, with a trusted certificate.

Every client follows the same sign-in sequence:

1. Discover OAuth metadata and register automatically with DCR.
2. Open the authorization page and inspect the client callback address and requested access.
3. Choose **Continue to device approval**, open the approval link, and approve the displayed code in the existing PocketShell or DataOps account.
4. Return to the connector authorization tab and choose **Finish connection**. The browser returns to the assistant; the client completes its PKCE exchange.

No bearer token, SSH key or pin needs to be pasted into the assistant.

## ChatGPT and dots

1. On ChatGPT web, open **Plugins** → plus → **Add custom MCP server**.
2. Enter a name and the full MCP URL. Select **OAuth** and automatic/dynamic client registration. Leave static client credentials empty.
3. Review the warning and choose **Create as a plugin**. Complete the sign-in sequence above when prompted.
4. Install the resulting plugin. In a new conversation, type `@` and select it. For dots, enable the installed plugin for the account/dot and ask it to call `hosts` explicitly.
5. Check the discovered tools, connected account and write-approval settings. Start with `hosts`, then `ls`, `status` and `capture`. Use a disposable session for an authorized `start` → `send` → `capture` → `stop` test.

Some interfaces still use **Settings → Apps/Connectors → Advanced → Developer mode**. Creation and write access depend on account rollout, workspace permissions and security restrictions. If the custom-server entry is unavailable, an account/workspace administrator must resolve access. Refresh the connection after changing tool metadata.

Sources: [custom MCP setup](https://developers.openai.com/api/docs/guides/custom-mcp-server), [dots app access](https://learn.chatgpt.com/docs/dots/computers-and-apps).

## Grok Bot

In the Bot's chat, ask: “Add a custom MCP server named PocketShell, type Remote HTTPS, at `https://mcp.example.com/mcp`, using OAuth and automatic registration.” Confirm the setup card, authenticate through the browser, then attach the connector with `@` and request `hosts`.

Use **Remote HTTPS** so authorization stays in the connector service rather than a command on the Bot computer. Installed connectors are account-wide. A Team Bot using OAuth requires each teammate's own sign-in. A grok.com connector and a Grok Bot connector are separate surfaces; test the Bot itself.

Sources: [Grok Bot app connections](https://docs.x.ai/grok-bot/computer-and-apps), [Team Bot remote MCP authentication](https://docs.x.ai/grok-bot/team-bots), [Cursor staff instructions for custom Bot connectors](https://forum.cursor.com/t/grokbot-custom-connectors/169965/5).

## Claude web and Desktop

Open **Customize → Connectors → Add custom connector**, enter the name and URL, choose sign-in, and select **Register automatically** as the OAuth client method. Finish authorization and enable the connector for the conversation. Team/Enterprise owners may need to add it to the organization first. Desktop remote connectors also connect from the provider cloud.

Source: [Claude custom connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

## Claude Code

```sh
claude mcp add --transport http pocketshell https://mcp.example.com/mcp
```

Open `/mcp`, select the server and authenticate. Use a separate name and the DataOps URL for DataOps. Source: [Claude Code MCP](https://code.claude.com/docs/en/mcp).

## Cursor

Add a remote HTTP server in the MCP settings, or add this configuration to the MCP configuration file:

```json
{"mcpServers":{"pocketshell":{"url":"https://mcp.example.com/mcp"}}}
```

Choose Connect/Authenticate and finish browser authorization. No Authorization header belongs in the configuration. Source: [Cursor MCP](https://cursor.com/docs/mcp).

## Codex

```sh
codex mcp add pocketshell --url https://mcp.example.com/mcp
codex mcp login pocketshell --oauth-client-registration dcr
```

Finish browser approval. Use another server name for DataOps. Source: [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp).

## MCP Inspector

Run `npx @modelcontextprotocol/inspector` and select its web interface, HTTP transport and the MCP URL. Use the OAuth controls to discover metadata, register and authorize; follow the same browser steps. Run **List Tools**, inspect schemas/annotations, then call a read tool. Do not paste an existing application token or disable TLS verification.

`npm test` also runs Inspector's CLI over trusted HTTPS for both services, including DCR/PKCE and a synthetic device-approval bridge. It lists every tool with schema checks and calls a read tool. The synthetic upstream does not prove a real account or deployed endpoint works.

## Record acceptance separately

For both services, record the deployed revision, client name/version, DCR/PKCE result, read call result, reconnect/refresh result and upstream-revoke result. ChatGPT/dots and Grok Bot must pass on their actual accounts before production acceptance; Claude and Inspector are additional interoperability targets. Do not substitute local protocol tests for these results.
