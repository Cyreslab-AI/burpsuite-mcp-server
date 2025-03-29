# Burpsuite MCP Server

A Model Context Protocol (MCP) server that provides an interface for interacting with Burpsuite Professional's scanning and proxy functionality.

## Overview

This MCP server allows AI assistants to interact with Burpsuite Professional for web security testing and vulnerability scanning. It provides tools for:

- Starting vulnerability scans on target URLs
- Checking scan status and retrieving results
- Accessing HTTP/HTTPS traffic captured by Burp Proxy
- Viewing site structure discovered during scanning

## Features

### Tools

The server exposes the following tools:

1. **start_scan**: Start a new vulnerability scan on a target URL

   - Parameters:
     - `target`: Target URL to scan (e.g., https://example.com)
     - `scan_type`: Type of scan to perform (passive, active, or full)

2. **get_scan_status**: Check the status of a running scan

   - Parameters:
     - `scan_id`: ID of the scan to check

3. **get_scan_issues**: Get vulnerability issues found in a scan

   - Parameters:
     - `scan_id`: ID of the scan
     - `severity`: Filter issues by severity (high, medium, low, info, or all)

4. **get_proxy_history**: Get HTTP/HTTPS traffic captured by Burp Proxy

   - Parameters:
     - `host`: Filter by host (optional)
     - `method`: Filter by HTTP method (optional)
     - `status_code`: Filter by HTTP status code (optional)
     - `limit`: Maximum number of items to return (default: 10)

5. **get_site_map**: Get the site structure discovered during scanning and browsing
   - Parameters:
     - `host`: Filter by host (optional)
     - `with_parameters`: Only show URLs with parameters (optional)
     - `limit`: Maximum number of items to return (default: 20)

### Resources

The server provides the following resources:

1. **Scan Results**: `burpsuite://scan/{scanId}`
2. **Issue Details**: `burpsuite://scan/{scanId}/issue/{issueId}`
3. **Proxy History**: `burpsuite://proxy/history`
4. **Proxy History Item**: `burpsuite://proxy/history/{itemId}`
5. **Site Map**: `burpsuite://sitemap`

## Installation

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
         "env": {},
         "disabled": false,
         "autoApprove": []
       }
     }
   }
   ```

## Future Enhancements

This server currently provides mock functionality. To connect it to a real Burpsuite Professional instance:

1. Configure Burpsuite Professional to expose its REST API
2. Update the server implementation to connect to the Burpsuite REST API
3. Add authentication mechanisms for secure API communication

## Example Usage

Here are some examples of how to use the Burpsuite MCP server with an AI assistant:

### Starting a Scan

```
Use the Burpsuite MCP server to scan example.com for vulnerabilities.
```

### Viewing Proxy History

```
Show me the HTTP traffic captured by Burp Proxy for domain example.com.
```

### Analyzing Vulnerabilities

```
What high severity vulnerabilities were found in the latest scan?
```
