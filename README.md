# Burp Suite MCP Server

[![smithery badge](https://smithery.ai/badge/@Cyreslab-AI/burpsuite-mcp-server)](https://smithery.ai/server/@Cyreslab-AI/burpsuite-mcp-server)
A Model Context Protocol (MCP) server that calls Burp Suite Professional's built-in local REST API to launch scans and retrieve scan status/issues.

<a href="https://glama.ai/mcp/servers/@Cyreslab-AI/burpsuite-mcp-server">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@Cyreslab-AI/burpsuite-mcp-server/badge" alt="Burpsuite Server MCP server" />
</a>

## Overview

This MCP server allows AI assistants to drive Burp Suite Professional's scanner for web security testing. It provides tools for:

- Starting vulnerability scans on target URLs
- Checking scan status
- Retrieving vulnerability issues found by a scan

It talks to Burp Suite Professional's own local REST API — the same API surface Burp exposes for its own automation, not a separate hosted product. (Burp Suite **Enterprise** has a different, GraphQL-first API aimed at CI/CD; this server does not use it.)

`get_proxy_history` and `get_site_map` are kept in the tool list for interface compatibility with earlier versions of this server, but Burp Suite Professional's REST API has no endpoint for proxy history or the site map — see [Known limitation](#known-limitation-proxy-history--site-map) below.

## Setting up Burp Suite's REST API

1. Open Burp Suite Professional, go to **Settings > Suite > REST API**.
2. Check **"Service running"**.
3. Note (or change) the service URL/port — the default is `http://127.0.0.1:1337` (loopback only by default; PortSwigger advises against binding to a non-loopback interface on an untrusted network).
4. Create an API key. **The key is only shown once, at creation** — copy it somewhere safe.

Burp's REST API is accessed as `http://<host>:<port>/<api-key>/v0.1/...`. It is also self-documenting: once the service is running, browsing to `http://<host>:<port>/<api-key>/v0.1/<api-key>` shows the exact request/response schema for your installed Burp version. PortSwigger does not publish a full static schema for this API, so if a tool's output looks off, that page is the source of truth.

## Configuration

This server requires two environment variables — it will refuse to start without them:

| Variable        | Description                                                         |
| --------------- | -------------------------------------------------------------------- |
| `BURP_API_URL`  | Base URL of Burp's REST API service, e.g. `http://localhost:1337`   |
| `BURP_API_KEY`  | The API key generated in Settings > Suite > REST API                |

## Features

### Tools

The server exposes the following tools:

1. **start_scan**: Start a new vulnerability scan on a target URL (`POST /v0.1/scan`). This launches a real scan against the target and generates live traffic to it.

   - Parameters:
     - `target` (required): Target URL to scan (e.g., `https://example.com`)
     - `scope` (optional): Passed through as-is to Burp's request body (e.g. `{ include: [...], exclude: [...] }`). The exact shape isn't published by PortSwigger — check your instance's self-documenting API if unsure.
     - `scan_configurations` (optional): Passed through as-is (e.g. references to named configurations from Scanner > Scan configurations). If omitted, Burp uses its default crawl-and-audit configuration.
     - `application_logins` (optional): `[{ username, password }, ...]` for authenticated scanning, passed through as-is.

2. **get_scan_status**: Check the status of a scan (`GET /v0.1/scan/{task_id}`)

   - Parameters:
     - `scan_id`: Task id of the scan (returned by `start_scan`)

3. **get_scan_issues**: Get vulnerability issues found so far by a scan. Issues come back embedded in the same `GET /v0.1/scan/{task_id}` response as scan status — there's no separate issues endpoint.

   - Parameters:
     - `scan_id`: Task id of the scan
     - `severity`: Filter issues by severity (`high`, `medium`, `low`, `info`, or `all`)

4. **get_proxy_history** / **get_site_map**: Not supported by Burp Suite Professional's REST API. Calling either returns a clear explanatory error rather than fabricated data. See [Known limitation](#known-limitation-proxy-history--site-map).

Note: earlier versions of this server accepted a `scan_type` (`passive`/`active`/`full`) parameter on `start_scan`. That parameter had no real equivalent in Burp's REST API and has been replaced with the `scope`/`scan_configurations`/`application_logins` fields above, which map onto Burp's actual request body.

### Known limitation: proxy history & site map

Burp Suite Professional's REST API only supports launching scans and reading scan status/issues — it has no endpoint for HTTP proxy history or the site map. That data is only reachable through:

- Burp's separate **Montoya extension API** (a Java/Kotlin/Python extension you write and load into Burp, which can expose whatever data you need over its own interface), or
- The desktop UI directly (**Proxy > HTTP history**, **Target > Site map**).

Rather than remove `get_proxy_history`/`get_site_map` outright (which could silently break existing configurations that reference them by name) or fake their output (which is the exact problem this rewrite fixes), both tools are kept and simply return an explanatory error when called.

## Error handling

All tools call the real Burp REST API and surface real failures instead of falling back to mock data:

- **Connection refused / Burp not running / REST API not enabled**: returns a clear message telling you to check that Burp is running with the REST API enabled and that `BURP_API_URL` is correct.
- **401/403 (bad API key)**: returns a message telling you to check `BURP_API_KEY`.
- **404**: returns a message covering the two likely causes — an unknown/expired scan id, or a `BURP_API_URL`/`BURP_API_KEY` mismatch.
- Any other non-2xx response is surfaced with the HTTP status and response body.

## Installation

### Installing via Smithery

To install Burp Suite Server for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@Cyreslab-AI/burpsuite-mcp-server):

```bash
npx -y @smithery/cli install @Cyreslab-AI/burpsuite-mcp-server --client claude
```

### Manual Installation

1. Build the server:

   ```bash
   cd /path/to/burpsuite-server
   npm install
   npm run build
   ```

2. Add the server to your MCP settings configuration file:
   ```json
   {
     "mcpServers": {
       "burpsuite": {
         "command": "node",
         "args": ["/path/to/burpsuite-server/build/index.js"],
         "env": {
           "BURP_API_URL": "http://localhost:1337",
           "BURP_API_KEY": "your-api-key-here"
         },
         "disabled": false,
         "autoApprove": []
       }
     }
   }
   ```

## Example Usage

Here are some examples of how to use the Burp Suite MCP server with an AI assistant:

### Starting a Scan

```
Use the Burp Suite MCP server to scan example.com for vulnerabilities.
```

### Checking Scan Status

```
What's the status of scan <scan_id>?
```

### Analyzing Vulnerabilities

```
What high severity vulnerabilities were found in scan <scan_id>?
```
