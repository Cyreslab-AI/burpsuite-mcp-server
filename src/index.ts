#!/usr/bin/env node

/**
 * Burp Suite MCP Server
 *
 * This server provides an interface for interacting with Burp Suite
 * Professional's scanner through the Model Context Protocol.
 *
 * It calls Burp Suite Professional's built-in local REST API. That API
 * is enabled from the Burp desktop application under
 * Settings > Suite > REST API ("Service running"), which also generates
 * the API key used below. The default base URL is http://127.0.0.1:1337
 * and the access pattern is:
 *
 *   http://<host>:<port>/<api-key>/v0.1/...
 *
 * IMPORTANT: PortSwigger does not publish a full static schema for this
 * API. It is self-documenting: once Burp is running with the REST API
 * enabled, browse to
 *
 *   http://<host>:<port>/<api-key>/v0.1/<api-key>
 *
 * to see the exact request/response shapes for your Burp version. The
 * request/response handling below is built from PortSwigger's public
 * documentation plus cross-referencing third-party clients of this same
 * API (e.g. the "burpa" project), and defensively tolerates minor field
 * naming differences. It has been verified by code review and against
 * connection-failure paths, but NOT against a live Burp Suite instance
 * (none was available while building this).
 *
 * Burp Suite Professional's REST API only supports launching scans and
 * reading scan status/issues. It has no endpoint for proxy history or
 * the site map — that data is only reachable through Burp's separate
 * Montoya extension API or the desktop UI. The get_proxy_history and
 * get_site_map tools are kept for interface compatibility, but they
 * return an explanatory error instead of fabricated data.
 */

import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import {
  Server,
  ProtocolError,
  ProtocolErrorCode,
} from "@modelcontextprotocol/server";
import axios, { AxiosInstance } from "axios";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BURP_API_URL = process.env.BURP_API_URL;
const BURP_API_KEY = process.env.BURP_API_KEY;

if (!BURP_API_URL) {
  throw new Error(
    "BURP_API_URL environment variable is required (e.g. http://localhost:1337). " +
      'Enable the REST API in Burp Suite Professional under Settings > Suite > REST API ' +
      '("Service running") and set this to the configured service URL.',
  );
}

if (!BURP_API_KEY) {
  throw new Error(
    "BURP_API_KEY environment variable is required. Generate an API key from Burp " +
      "Suite Professional's Settings > Suite > REST API panel and set this to that key's value.",
  );
}

// ---------------------------------------------------------------------------
// Burp Suite Professional REST API client
// ---------------------------------------------------------------------------

interface StartScanParams {
  target: string;
  /**
   * Passed through as-is to Burp's `scope` field. Shape is not fully
   * documented publicly; check your instance's self-documenting API.
   */
  scope?: unknown;
  /**
   * Passed through as-is to Burp's `scan_configurations` field (e.g.
   * references to named configurations from Scanner > Scan
   * configurations). If omitted, Burp uses its default configuration
   * (a full crawl and audit).
   */
  scanConfigurations?: unknown[];
  /** Passed through as-is to Burp's `application_logins` field. */
  applicationLogins?: unknown[];
}

class BurpApiClient {
  private readonly http: AxiosInstance;

  constructor(baseUrl: string, apiKey: string) {
    const trimmedBase = baseUrl.replace(/\/+$/, "");
    this.http = axios.create({
      baseURL: `${trimmedBase}/${apiKey}/v0.1`,
      timeout: 15000,
      headers: { "Content-Type": "application/json" },
    });
  }

  /**
   * Launch a new scan via POST /v0.1/scan.
   *
   * Burp responds with an empty body and the new task's location in the
   * `Location` header. We defensively also check the response body for
   * a task/id field in case a given Burp version returns one directly.
   */
  async startScan(params: StartScanParams): Promise<{ taskId: string }> {
    const body: Record<string, unknown> = { urls: [params.target] };
    if (params.scope !== undefined) body.scope = params.scope;
    if (params.scanConfigurations !== undefined) {
      body.scan_configurations = params.scanConfigurations;
    }
    if (params.applicationLogins !== undefined) {
      body.application_logins = params.applicationLogins;
    }

    const response = await this.http.post("/scan", body);

    const locationHeader =
      response.headers?.["location"] ?? response.headers?.["Location"];
    let taskId: string | undefined;
    if (typeof locationHeader === "string" && locationHeader.length > 0) {
      const segments = locationHeader.split("/").filter(Boolean);
      taskId = segments[segments.length - 1];
    }

    if (!taskId) {
      const data = response.data as Record<string, unknown> | undefined;
      const fallback = data?.["task_id"] ?? data?.["id"];
      if (typeof fallback === "string" || typeof fallback === "number") {
        taskId = String(fallback);
      }
    }

    if (!taskId) {
      throw new Error(
        "Burp accepted the scan request but did not return a task id " +
          "(no Location header and no task_id/id field in the response body). " +
          "Check your Burp version's self-documented API for the exact response shape.",
      );
    }

    return { taskId };
  }

  /**
   * Fetch a scan's current status/metrics/issues via GET /v0.1/scan/{task_id}.
   * Issues (when present) come back embedded in this same response.
   */
  async getScan(taskId: string): Promise<Record<string, unknown>> {
    const response = await this.http.get(
      `/scan/${encodeURIComponent(taskId)}`,
    );
    return response.data as Record<string, unknown>;
  }
}

const burpClient = new BurpApiClient(BURP_API_URL, BURP_API_KEY);

// ---------------------------------------------------------------------------
// Response normalization helpers
// ---------------------------------------------------------------------------

/**
 * Normalized view of a single Burp issue. Field names on the raw API
 * response are not fully confirmed publicly, so this reads several
 * plausible/known key names and degrades gracefully instead of throwing.
 */
interface NormalizedIssue {
  severity: string;
  confidence: string;
  name: string;
  type_index?: unknown;
  host: string;
  path: string;
  description?: string;
  remediation?: string;
  evidence?: unknown;
}

function extractIssues(scanData: Record<string, unknown>): NormalizedIssue[] {
  const events =
    (scanData["issue_events"] as unknown[] | undefined) ??
    (scanData["issues"] as unknown[] | undefined) ??
    [];

  if (!Array.isArray(events)) {
    return [];
  }

  return events.map((event) => {
    const record = (event ?? {}) as Record<string, unknown>;
    const issue = (record["issue"] as Record<string, unknown> | undefined) ??
      record;
    const issueType =
      (issue["issue_type"] as Record<string, unknown> | undefined) ?? {};

    return {
      severity: String(
        issue["severity"] ?? issue["original_severity"] ?? "unknown",
      ),
      confidence: String(
        issue["confidence"] ?? issue["original_confidence"] ?? "unknown",
      ),
      name: String(
        issueType["name"] ?? issue["name"] ?? "Unknown issue",
      ),
      type_index: issueType["type_index"] ?? issue["type_index"],
      host: String(issue["origin"] ?? issue["host"] ?? ""),
      path: String(issue["path"] ?? ""),
      description:
        (issue["description_html"] as string | undefined) ??
        (issue["description"] as string | undefined),
      remediation:
        (issue["remediation_html"] as string | undefined) ??
        (issue["remediation"] as string | undefined),
      evidence: issue["evidence"],
    };
  });
}

function matchesSeverityFilter(issue: NormalizedIssue, filter: string): boolean {
  if (filter === "all") return true;
  const severity = issue.severity.toLowerCase();
  if (filter === "info") {
    return severity === "info" || severity === "information";
  }
  return severity === filter;
}

/**
 * Convert an error thrown by the Burp API client into a clear
 * ProtocolError instead of ever falling back to fabricated data.
 */
function mapBurpApiError(error: unknown, context: string): ProtocolError {
  if (axios.isAxiosError(error)) {
    if (!error.response) {
      const reason = error.code ? ` (${error.code})` : "";
      return new ProtocolError(
        ProtocolErrorCode.InternalError,
        `Could not reach the Burp Suite REST API at ${BURP_API_URL}${reason} while ${context}. ` +
          'Confirm Burp Suite Professional is running with the REST API enabled ' +
          '(Settings > Suite > REST API > "Service running"), and that BURP_API_URL ' +
          `points at the correct host and port. Underlying error: ${error.message}`,
      );
    }

    const status = error.response.status;

    if (status === 401 || status === 403) {
      return new ProtocolError(
        ProtocolErrorCode.InternalError,
        `Burp Suite REST API rejected the request (HTTP ${status}) while ${context}. ` +
          "Confirm BURP_API_KEY is correct and that key is still enabled in " +
          "Settings > Suite > REST API.",
      );
    }

    if (status === 404) {
      return new ProtocolError(
        ProtocolErrorCode.InternalError,
        `Burp Suite REST API returned 404 Not Found while ${context}. ` +
          "This usually means the scan id does not exist (it may have been " +
          "cleared, or belongs to a different Burp session), or that " +
          "BURP_API_URL/BURP_API_KEY do not match the base path Burp expects " +
          "(http://<host>:<port>/<api-key>/v0.1/...).",
      );
    }

    const body =
      typeof error.response.data === "string"
        ? error.response.data
        : JSON.stringify(error.response.data);
    return new ProtocolError(
      ProtocolErrorCode.InternalError,
      `Burp Suite REST API error (HTTP ${status}) while ${context}: ${body || error.message}`,
    );
  }

  const message = error instanceof Error ? error.message : String(error);
  return new ProtocolError(
    ProtocolErrorCode.InternalError,
    `Unexpected error while ${context}: ${message}`,
  );
}

/**
 * Burp task ids are plain integers, so a caller may reasonably pass
 * scan_id as either a string or a JSON number. Normalize to a string
 * (used directly in the URL path) and reject anything else.
 */
function coerceScanId(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

function unsupportedFeatureMessage(toolName: "get_proxy_history" | "get_site_map"): string {
  const feature = toolName === "get_proxy_history" ? "proxy history" : "the site map";
  return (
    `Not available: Burp Suite Professional's REST API does not expose ${feature}. ` +
    "The local REST API (http://<host>:<port>/<api-key>/v0.1/...) only supports " +
    "launching scans and reading scan status/issues. Proxy history and site map " +
    "data are only reachable through Burp's separate Montoya extension API " +
    "(a Java/Kotlin/Python extension running inside Burp) or the desktop UI " +
    "(Proxy > HTTP history, Target > Site map). This tool is kept for interface " +
    "compatibility but intentionally returns this message instead of fabricated data."
  );
}

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------

const server = new Server(
  {
    name: "burpsuite-server",
    version: "0.2.0",
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

/**
 * Handler for listing available tools.
 */
server.setRequestHandler("tools/list", async (): Promise<any> => {
  return {
    tools: [
      {
        name: "start_scan",
        description:
          "Start a new vulnerability scan on a target URL using Burp Suite " +
          "Professional's REST API (POST /v0.1/scan). Returns a scan_id " +
          "(Burp task id) to poll with get_scan_status/get_scan_issues. " +
          "This launches a real scan against the target and will generate " +
          "live traffic to it.",
        inputSchema: {
          type: "object",
          properties: {
            target: {
              type: "string",
              description: "Target URL to scan (e.g., https://example.com)",
            },
            scope: {
              type: "object",
              description:
                "Optional scope object passed through as-is to Burp's scan " +
                "request body (e.g. { include: [...], exclude: [...] }). " +
                "The exact shape isn't published by PortSwigger; confirm it " +
                "against your Burp instance's self-documenting API " +
                "(http://<host>:<port>/<api-key>/v0.1/<api-key>) if unsure.",
            },
            scan_configurations: {
              type: "array",
              items: {},
              description:
                "Optional list of scan configuration references (e.g. named " +
                "configurations from Scanner > Scan configurations), passed " +
                "through as-is. If omitted, Burp uses its default crawl-and-audit " +
                "configuration.",
            },
            application_logins: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  username: { type: "string" },
                  password: { type: "string" },
                },
              },
              description:
                "Optional credentials for authenticated scanning, passed " +
                "through as-is to Burp's scan request body.",
            },
          },
          required: ["target"],
        },
        outputSchema: {
          type: "object",
          properties: {
            scan_id: { type: "string" },
            target: { type: "string" },
            message: { type: "string" },
          },
          required: ["scan_id", "target", "message"],
        },
        annotations: {
          title: "Start Burp Scan",
          readOnlyHint: false,
          destructiveHint: true,
          idempotentHint: false,
          openWorldHint: true,
        },
      },
      {
        name: "get_scan_status",
        description:
          "Check the status of a scan previously started with start_scan, via " +
          "Burp's GET /v0.1/scan/{task_id}.",
        inputSchema: {
          type: "object",
          properties: {
            scan_id: {
              type: "string",
              description: "Task id of the scan to check (returned by start_scan)",
            },
          },
          required: ["scan_id"],
        },
        outputSchema: {
          type: "object",
          properties: {
            scan_id: { type: "string" },
            status: {},
            metrics: {},
            issue_count: { type: "integer" },
          },
          required: ["scan_id", "status", "issue_count"],
        },
        annotations: {
          title: "Get Scan Status",
          readOnlyHint: true,
          openWorldHint: true,
        },
      },
      {
        name: "get_scan_issues",
        description:
          "Get vulnerability issues found so far by a scan, via Burp's " +
          "GET /v0.1/scan/{task_id} (issues are embedded in the scan status response).",
        inputSchema: {
          type: "object",
          properties: {
            scan_id: {
              type: "string",
              description: "Task id of the scan (returned by start_scan)",
            },
            severity: {
              type: "string",
              enum: ["high", "medium", "low", "info", "all"],
              description: "Filter issues by severity (default: all)",
            },
          },
          required: ["scan_id"],
        },
        outputSchema: {
          type: "object",
          properties: {
            scan_id: { type: "string" },
            issue_count: { type: "integer" },
            issues: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  severity: { type: "string" },
                  confidence: { type: "string" },
                  name: { type: "string" },
                  type_index: {},
                  host: { type: "string" },
                  path: { type: "string" },
                  description: { type: "string" },
                  remediation: { type: "string" },
                  evidence: {},
                },
                required: ["severity", "confidence", "name", "host", "path"],
              },
            },
          },
          required: ["scan_id", "issue_count", "issues"],
        },
        annotations: {
          title: "Get Scan Issues",
          readOnlyHint: true,
          openWorldHint: true,
        },
      },
      {
        name: "get_proxy_history",
        description:
          "Not available via Burp Suite Professional's REST API. Kept for " +
          "interface compatibility; returns an explanatory error instead of " +
          "fabricated data. See tool output for details and alternatives " +
          "(Burp's Montoya extension API or the desktop UI).",
        inputSchema: {
          type: "object",
          properties: {
            host: { type: "string", description: "Filter by host (optional)" },
            method: {
              type: "string",
              description: "Filter by HTTP method (optional)",
            },
            status_code: {
              type: "number",
              description: "Filter by HTTP status code (optional)",
            },
            limit: {
              type: "number",
              description: "Maximum number of items to return (default: 10)",
            },
          },
        },
        outputSchema: {
          type: "object",
          properties: {
            available: { type: "boolean" },
            message: { type: "string" },
          },
          required: ["available", "message"],
        },
        annotations: {
          title: "Get Proxy History (Not Available)",
          readOnlyHint: true,
          openWorldHint: true,
        },
      },
      {
        name: "get_site_map",
        description:
          "Not available via Burp Suite Professional's REST API. Kept for " +
          "interface compatibility; returns an explanatory error instead of " +
          "fabricated data. See tool output for details and alternatives " +
          "(Burp's Montoya extension API or the desktop UI).",
        inputSchema: {
          type: "object",
          properties: {
            host: { type: "string", description: "Filter by host (optional)" },
            with_parameters: {
              type: "boolean",
              description: "Only show URLs with parameters (optional)",
            },
            limit: {
              type: "number",
              description: "Maximum number of items to return (default: 20)",
            },
          },
        },
        outputSchema: {
          type: "object",
          properties: {
            available: { type: "boolean" },
            message: { type: "string" },
          },
          required: ["available", "message"],
        },
        annotations: {
          title: "Get Site Map (Not Available)",
          readOnlyHint: true,
          openWorldHint: true,
        },
      },
    ],
  };
});

/**
 * Handler for tool calls.
 */
server.setRequestHandler("tools/call", async (request) => {
  switch (request.params.name) {
    case "start_scan": {
      const target = request.params.arguments?.target;
      if (!target || typeof target !== "string") {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidParams,
          "Target URL is required",
        );
      }

      try {
        // eslint-disable-next-line no-new
        new URL(target);
      } catch {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidParams,
          `"${target}" is not a valid URL`,
        );
      }

      const scope = request.params.arguments?.scope;
      const scanConfigurationsArg = request.params.arguments?.scan_configurations;
      const applicationLoginsArg = request.params.arguments?.application_logins;

      try {
        const { taskId } = await burpClient.startScan({
          target,
          scope,
          scanConfigurations: Array.isArray(scanConfigurationsArg)
            ? scanConfigurationsArg
            : undefined,
          applicationLogins: Array.isArray(applicationLoginsArg)
            ? applicationLoginsArg
            : undefined,
        });

        const result = {
          scan_id: taskId,
          target,
          message: `Scan started on ${target}. Poll get_scan_status with scan_id "${taskId}" for progress.`,
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
          structuredContent: result,
        };
      } catch (error) {
        throw mapBurpApiError(error, `starting a scan on ${target}`);
      }
    }

    case "get_scan_status": {
      const scanId = coerceScanId(request.params.arguments?.scan_id);
      if (!scanId) {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidParams,
          "scan_id is required",
        );
      }

      try {
        const data = await burpClient.getScan(scanId);
        const status = data["scan_status"] ?? data["status"] ?? "unknown";
        const metrics = data["scan_metrics"] ?? data["metrics"] ?? null;
        const issues = extractIssues(data);

        const result = {
          scan_id: scanId,
          status,
          metrics,
          issue_count: issues.length,
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
          structuredContent: result,
        };
      } catch (error) {
        throw mapBurpApiError(error, `getting status for scan ${scanId}`);
      }
    }

    case "get_scan_issues": {
      const scanId = coerceScanId(request.params.arguments?.scan_id);
      if (!scanId) {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidParams,
          "scan_id is required",
        );
      }

      const severityFilter =
        typeof request.params.arguments?.severity === "string"
          ? (request.params.arguments.severity as string).toLowerCase()
          : "all";

      try {
        const data = await burpClient.getScan(scanId);
        const issues = extractIssues(data).filter((issue) =>
          matchesSeverityFilter(issue, severityFilter),
        );

        const result = {
          scan_id: scanId,
          issue_count: issues.length,
          issues,
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
          structuredContent: result,
        };
      } catch (error) {
        throw mapBurpApiError(error, `getting issues for scan ${scanId}`);
      }
    }

    case "get_proxy_history":
    case "get_site_map": {
      const message = unsupportedFeatureMessage(request.params.name);
      return {
        content: [
          {
            type: "text",
            text: message,
          },
        ],
        structuredContent: { available: false, message },
        isError: true,
      };
    }

    default:
      throw new ProtocolError(
        ProtocolErrorCode.MethodNotFound,
        `Unknown tool: ${request.params.name}`,
      );
  }
});

/**
 * Start the server using stdio transport.
 */
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(
    `Burp Suite MCP server running on stdio (BURP_API_URL=${BURP_API_URL})`,
  );

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
