#!/usr/bin/env node

/**
 * Burpsuite MCP Server
 *
 * This server provides an interface for interacting with Burpsuite Professional's
 * scanning and proxy functionality through the Model Context Protocol.
 *
 * It implements mock functionality that can later be connected to the
 * Burpsuite REST API for real-world usage.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// Types for Burpsuite data structures

/**
 * Represents a vulnerability issue found during scanning
 */
interface Issue {
  id: string;
  name: string;
  severity: 'high' | 'medium' | 'low' | 'info';
  confidence: 'certain' | 'firm' | 'tentative';
  host: string;
  path: string;
  description: string;
  remediation: string;
  request?: string;
  response?: string;
}

/**
 * Represents a scan job
 */
interface Scan {
  id: string;
  target: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  startTime: string;
  endTime?: string;
  progress?: number;
  issues: Issue[];
}

/**
 * Represents an HTTP request/response pair in the proxy history
 */
interface ProxyHistoryItem {
  id: string;
  host: string;
  method: string;
  url: string;
  statusCode: number;
  request: string;
  response: string;
  time: string;
  size: number;
  mimeType: string;
}

/**
 * Represents a site map entry
 */
interface SiteMapItem {
  id: string;
  url: string;
  method: string;
  statusCode: number;
  mimeType: string;
  size: number;
  parameters: boolean;
}

// Mock data storage
const mockScans: { [id: string]: Scan } = {};
const mockProxyHistory: ProxyHistoryItem[] = [
  {
    id: "1",
    host: "example.com",
    method: "GET",
    url: "https://example.com/",
    statusCode: 200,
    request: "GET / HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\nAccept: */*\n\n",
    response: "HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 1256\n\n<!DOCTYPE html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples in documents.</p></body></html>",
    time: new Date().toISOString(),
    size: 1256,
    mimeType: "text/html"
  },
  {
    id: "2",
    host: "example.com",
    method: "GET",
    url: "https://example.com/assets/style.css",
    statusCode: 200,
    request: "GET /assets/style.css HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\nAccept: text/css\n\n",
    response: "HTTP/1.1 200 OK\nContent-Type: text/css\nContent-Length: 128\n\nbody { font-family: sans-serif; } h1 { color: #333; }",
    time: new Date().toISOString(),
    size: 128,
    mimeType: "text/css"
  }
];

const mockSiteMap: SiteMapItem[] = [
  {
    id: "1",
    url: "https://example.com/",
    method: "GET",
    statusCode: 200,
    mimeType: "text/html",
    size: 1256,
    parameters: false
  },
  {
    id: "2",
    url: "https://example.com/assets/style.css",
    method: "GET",
    statusCode: 200,
    mimeType: "text/css",
    size: 128,
    parameters: false
  },
  {
    id: "3",
    url: "https://example.com/login",
    method: "GET",
    statusCode: 200,
    mimeType: "text/html",
    size: 2048,
    parameters: false
  },
  {
    id: "4",
    url: "https://example.com/api/user",
    method: "POST",
    statusCode: 200,
    mimeType: "application/json",
    size: 512,
    parameters: true
  }
];

// Common vulnerability types for mock data
const commonVulnerabilities = [
  {
    name: "SQL Injection",
    description: "SQL injection vulnerability detected in parameter. The application appears to be vulnerable to SQL injection attacks, which could allow an attacker to manipulate database queries.",
    remediation: "Use parameterized queries or prepared statements instead of building SQL queries through string concatenation. Apply input validation and use an ORM if possible."
  },
  {
    name: "Cross-Site Scripting (XSS)",
    description: "Cross-site scripting vulnerability detected. The application reflects user input without proper encoding, which could allow attackers to inject malicious scripts.",
    remediation: "Implement proper output encoding for all user-controlled data. Use Content-Security-Policy headers and consider using frameworks that automatically escape output."
  },
  {
    name: "Insecure Direct Object Reference",
    description: "Insecure direct object reference vulnerability detected. The application exposes references to internal implementation objects, allowing attackers to manipulate these references to access unauthorized data.",
    remediation: "Implement proper access controls and use indirect reference maps. Validate that the user is authorized to access the requested object."
  },
  {
    name: "Information Disclosure",
    description: "Information disclosure vulnerability detected. The application reveals sensitive information such as server versions, file paths, or database details in responses.",
    remediation: "Configure proper error handling to avoid leaking sensitive information. Remove unnecessary headers and implement security headers like X-Content-Type-Options."
  }
];

// Helper function to generate mock issues for a scan
function generateMockIssues(host: string, count: number): Issue[] {
  const issues: Issue[] = [];
  const paths = ["/login", "/api/user", "/search", "/profile", "/admin", "/settings"];
  const severities: Array<'high' | 'medium' | 'low' | 'info'> = ['high', 'medium', 'low', 'info'];
  const confidences: Array<'certain' | 'firm' | 'tentative'> = ['certain', 'firm', 'tentative'];

  for (let i = 0; i < count; i++) {
    const vulnType = commonVulnerabilities[Math.floor(Math.random() * commonVulnerabilities.length)];
    const path = paths[Math.floor(Math.random() * paths.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const confidence = confidences[Math.floor(Math.random() * confidences.length)];

    issues.push({
      id: `issue-${i + 1}`,
      name: vulnType.name,
      severity,
      confidence,
      host,
      path,
      description: vulnType.description,
      remediation: vulnType.remediation,
      request: `GET ${path} HTTP/1.1\nHost: ${host}\nUser-Agent: Mozilla/5.0\n\n`,
      response: `HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Example response</body></html>`
    });
  }

  return issues;
}

/**
 * Create an MCP server for Burpsuite functionality
 */
const server = new Server(
  {
    name: "burpsuite-server",
    version: "0.1.0",
  },
  {
    capabilities: {
      resources: {},
      tools: {},
    },
  }
);

/**
 * Handler for listing available resources.
 * Exposes scan results and proxy history as resources.
 */
server.setRequestHandler(ListResourcesRequestSchema, async () => {
  const resources = [];

  // Add scan resources
  for (const [id, scan] of Object.entries(mockScans)) {
    resources.push({
      uri: `burpsuite://scan/${id}`,
      mimeType: "application/json",
      name: `Scan of ${scan.target}`,
      description: `Vulnerability scan of ${scan.target} (${scan.status})`
    });
  }

  // Add a proxy history resource
  resources.push({
    uri: `burpsuite://proxy/history`,
    mimeType: "application/json",
    name: "Proxy History",
    description: "HTTP/HTTPS traffic captured by Burp Proxy"
  });

  // Add a site map resource
  resources.push({
    uri: `burpsuite://sitemap`,
    mimeType: "application/json",
    name: "Site Map",
    description: "Structure of discovered websites"
  });

  return { resources };
});

/**
 * Handler for resource templates.
 * Defines templates for accessing specific scan results and proxy history items.
 */
server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
  return {
    resourceTemplates: [
      {
        uriTemplate: "burpsuite://scan/{scanId}",
        name: "Scan Results",
        mimeType: "application/json",
        description: "Results of a specific vulnerability scan"
      },
      {
        uriTemplate: "burpsuite://scan/{scanId}/issue/{issueId}",
        name: "Issue Details",
        mimeType: "application/json",
        description: "Details of a specific vulnerability issue"
      },
      {
        uriTemplate: "burpsuite://proxy/history/{itemId}",
        name: "Proxy History Item",
        mimeType: "application/json",
        description: "Details of a specific HTTP/HTTPS request/response pair"
      }
    ]
  };
});

/**
 * Handler for reading resources.
 * Retrieves scan results, issue details, or proxy history based on the URI.
 */
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const uri = request.params.uri;

  // Handle scan results
  if (uri.startsWith("burpsuite://scan/")) {
    const parts = uri.replace("burpsuite://scan/", "").split("/");
    const scanId = parts[0];

    if (!mockScans[scanId]) {
      throw new McpError(ErrorCode.InvalidRequest, `Scan ${scanId} not found`);
    }

    // Handle specific issue
    if (parts.length > 1 && parts[1] === "issue") {
      const issueId = parts[2];
      const issue = mockScans[scanId].issues.find(i => i.id === issueId);

      if (!issue) {
        throw new McpError(ErrorCode.InvalidRequest, `Issue ${issueId} not found in scan ${scanId}`);
      }

      return {
        contents: [{
          uri,
          mimeType: "application/json",
          text: JSON.stringify(issue, null, 2)
        }]
      };
    }

    // Return full scan
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(mockScans[scanId], null, 2)
      }]
    };
  }

  // Handle proxy history
  if (uri === "burpsuite://proxy/history") {
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(mockProxyHistory, null, 2)
      }]
    };
  }

  // Handle specific proxy history item
  if (uri.startsWith("burpsuite://proxy/history/")) {
    const itemId = uri.replace("burpsuite://proxy/history/", "");
    const item = mockProxyHistory.find(i => i.id === itemId);

    if (!item) {
      throw new McpError(ErrorCode.InvalidRequest, `Proxy history item ${itemId} not found`);
    }

    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(item, null, 2)
      }]
    };
  }

  // Handle site map
  if (uri === "burpsuite://sitemap") {
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(mockSiteMap, null, 2)
      }]
    };
  }

  throw new McpError(ErrorCode.InvalidRequest, `Resource not found: ${uri}`);
});

/**
 * Handler for listing available tools.
 * Exposes tools for scanning, retrieving scan status, and accessing proxy history.
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "start_scan",
        description: "Start a new vulnerability scan on a target URL",
        inputSchema: {
          type: "object",
          properties: {
            target: {
              type: "string",
              description: "Target URL to scan (e.g., https://example.com)"
            },
            scan_type: {
              type: "string",
              enum: ["passive", "active", "full"],
              description: "Type of scan to perform"
            }
          },
          required: ["target"]
        }
      },
      {
        name: "get_scan_status",
        description: "Check the status of a running scan",
        inputSchema: {
          type: "object",
          properties: {
            scan_id: {
              type: "string",
              description: "ID of the scan to check"
            }
          },
          required: ["scan_id"]
        }
      },
      {
        name: "get_scan_issues",
        description: "Get vulnerability issues found in a scan",
        inputSchema: {
          type: "object",
          properties: {
            scan_id: {
              type: "string",
              description: "ID of the scan"
            },
            severity: {
              type: "string",
              enum: ["high", "medium", "low", "info", "all"],
              description: "Filter issues by severity"
            }
          },
          required: ["scan_id"]
        }
      },
      {
        name: "get_proxy_history",
        description: "Get HTTP/HTTPS traffic captured by Burp Proxy",
        inputSchema: {
          type: "object",
          properties: {
            host: {
              type: "string",
              description: "Filter by host (optional)"
            },
            method: {
              type: "string",
              description: "Filter by HTTP method (optional)"
            },
            status_code: {
              type: "number",
              description: "Filter by HTTP status code (optional)"
            },
            limit: {
              type: "number",
              description: "Maximum number of items to return (default: 10)"
            }
          }
        }
      },
      {
        name: "get_site_map",
        description: "Get the site structure discovered during scanning and browsing",
        inputSchema: {
          type: "object",
          properties: {
            host: {
              type: "string",
              description: "Filter by host (optional)"
            },
            with_parameters: {
              type: "boolean",
              description: "Only show URLs with parameters (optional)"
            },
            limit: {
              type: "number",
              description: "Maximum number of items to return (default: 20)"
            }
          }
        }
      }
    ]
  };
});

/**
 * Handler for tool calls.
 * Implements the functionality for each tool.
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  switch (request.params.name) {
    case "start_scan": {
      const target = String(request.params.arguments?.target);
      const scanType = String(request.params.arguments?.scan_type || "passive");

      if (!target) {
        throw new McpError(ErrorCode.InvalidParams, "Target URL is required");
      }

      // Create a new scan
      const scanId = `scan-${Date.now()}`;
      const scan: Scan = {
        id: scanId,
        target,
        status: "running",
        startTime: new Date().toISOString(),
        progress: 0,
        issues: []
      };

      mockScans[scanId] = scan;

      // Simulate scan completion after a delay (in a real implementation, this would be async)
      setTimeout(() => {
        const issueCount = scanType === "passive" ? 3 : scanType === "active" ? 8 : 15;
        mockScans[scanId].issues = generateMockIssues(new URL(target).hostname, issueCount);
        mockScans[scanId].status = "completed";
        mockScans[scanId].endTime = new Date().toISOString();
        mockScans[scanId].progress = 100;
      }, 5000);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            scan_id: scanId,
            message: `Started ${scanType} scan on ${target}`,
            status: "running"
          }, null, 2)
        }]
      };
    }

    case "get_scan_status": {
      const scanId = String(request.params.arguments?.scan_id);

      if (!scanId || !mockScans[scanId]) {
        throw new McpError(ErrorCode.InvalidRequest, `Scan ${scanId} not found`);
      }

      const scan = mockScans[scanId];

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            scan_id: scanId,
            target: scan.target,
            status: scan.status,
            progress: scan.progress,
            start_time: scan.startTime,
            end_time: scan.endTime,
            issue_count: scan.issues.length
          }, null, 2)
        }]
      };
    }

    case "get_scan_issues": {
      const scanId = String(request.params.arguments?.scan_id);
      const severity = String(request.params.arguments?.severity || "all");

      if (!scanId || !mockScans[scanId]) {
        throw new McpError(ErrorCode.InvalidRequest, `Scan ${scanId} not found`);
      }

      const scan = mockScans[scanId];
      let issues = scan.issues;

      // Filter by severity if specified
      if (severity !== "all") {
        issues = issues.filter(issue => issue.severity === severity);
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            scan_id: scanId,
            target: scan.target,
            issue_count: issues.length,
            issues: issues.map(issue => ({
              id: issue.id,
              name: issue.name,
              severity: issue.severity,
              confidence: issue.confidence,
              host: issue.host,
              path: issue.path
            }))
          }, null, 2)
        }]
      };
    }

    case "get_proxy_history": {
      const host = request.params.arguments?.host as string | undefined;
      const method = request.params.arguments?.method as string | undefined;
      const statusCode = request.params.arguments?.status_code as number | undefined;
      const limit = Number(request.params.arguments?.limit || 10);

      let history = [...mockProxyHistory];

      // Apply filters
      if (host) {
        history = history.filter(item => item.host.includes(host));
      }

      if (method) {
        history = history.filter(item => item.method === method.toUpperCase());
      }

      if (statusCode) {
        history = history.filter(item => item.statusCode === statusCode);
      }

      // Apply limit
      history = history.slice(0, limit);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            total_items: history.length,
            items: history.map(item => ({
              id: item.id,
              host: item.host,
              method: item.method,
              url: item.url,
              status_code: item.statusCode,
              time: item.time,
              size: item.size,
              mime_type: item.mimeType
            }))
          }, null, 2)
        }]
      };
    }

    case "get_site_map": {
      const host = request.params.arguments?.host as string | undefined;
      const withParameters = request.params.arguments?.with_parameters as boolean | undefined;
      const limit = Number(request.params.arguments?.limit || 20);

      let siteMap = [...mockSiteMap];

      // Apply filters
      if (host) {
        siteMap = siteMap.filter(item => new URL(item.url).hostname.includes(host));
      }

      if (withParameters) {
        siteMap = siteMap.filter(item => item.parameters);
      }

      // Apply limit
      siteMap = siteMap.slice(0, limit);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            total_items: siteMap.length,
            items: siteMap
          }, null, 2)
        }]
      };
    }

    default:
      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${request.params.name}`);
  }
});

/**
 * Start the server using stdio transport.
 */
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Burpsuite MCP server running on stdio");

  // Handle errors
  server.onerror = (error) => {
    console.error("[MCP Error]", error);
  };

  // Handle process termination
  process.on("SIGINT", async () => {
    await server.close();
    process.exit(0);
  });
}

main().catch((error) => {
  console.error("Server error:", error);
  process.exit(1);
});
