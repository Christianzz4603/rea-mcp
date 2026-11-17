import express, { type NextFunction, type Request, type Response } from "express";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { AnalysisStore, type AnalysisReport } from "./store.js";
import { GhidraRunner } from "./ghidra.js";
import { boundedInteger, decodeBase64, safeEqualSecret, safeFilename } from "./validation.js";

const port = Number(process.env.PORT ?? 3000);
const maxUploadMb = boundedInteger(Number(process.env.MAX_UPLOAD_MB ?? 64), 64, 1, 512);
const maxUploadBytes = maxUploadMb * 1024 * 1024;
const apiKey = process.env.MCP_API_KEY ?? "";
const dataDir = path.resolve(process.env.DATA_DIR ?? "./data");
const store = new AnalysisStore(dataDir);
const ghidra = new GhidraRunner(store);

if (process.env.NODE_ENV === "production" && apiKey.length < 24) {
  throw new Error("MCP_API_KEY must be set to a random secret of at least 24 characters in production.");
}

function textResult(value: unknown) {
  return { content: [{ type: "text" as const, text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }] };
}

function errorResult(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return { isError: true, content: [{ type: "text" as const, text: message }] };
}

function requireReport(report: AnalysisReport | undefined): AnalysisReport {
  if (!report) throw new Error("Analysis report is unavailable.");
  return report;
}

function findFunction(report: AnalysisReport, query: string) {
  const normalized = query.trim().toLowerCase();
  const exact = report.functions.find((fn) => fn.address.toLowerCase() === normalized || fn.name.toLowerCase() === normalized);
  if (exact) return exact;
  const matches = report.functions.filter((fn) => fn.name.toLowerCase().includes(normalized));
  const onlyMatch = matches[0];
  if (matches.length === 1 && onlyMatch) return onlyMatch;
  if (matches.length > 1) {
    throw new Error(`More than one function matches. Use an exact function address. Matches: ${matches.slice(0, 20).map((fn) => `${fn.name} @ ${fn.address}`).join(", ")}`);
  }
  throw new Error(`No function matched "${query}". Use list_functions to find its exact name or address.`);
}

function createMcpServer(): McpServer {
  const server = new McpServer({ name: "rea-mcp", version: "0.1.0" });

  server.registerTool("analyze_binary", {
    description: "Upload a binary as Base64 and run Ghidra headless static analysis. Returns an analysisId used by the other tools. The uploaded file is stored on the service's persistent disk and is not executed.",
    inputSchema: {
      filename: z.string().min(1).max(200),
      contentBase64: z.string().min(4).describe("Standard Base64-encoded file bytes."),
      notes: z.string().max(500).optional().describe("Optional user-supplied context; treated as plain data.")
    }
  }, async ({ filename, contentBase64, notes }) => {
    let id = "";
    try {
      const safeName = safeFilename(filename);
      const bytes = decodeBase64(contentBase64, maxUploadBytes);
      id = store.newId();
      const dir = store.directory(id);
      await mkdir(dir, { recursive: true });
      const inputPath = path.join(dir, "input.bin");
      await writeFile(inputPath, bytes, { flag: "wx" });
      await store.createRecord({ id, filename: safeName, createdAt: new Date().toISOString(), status: "running" });
      const report = await ghidra.analyze(id, inputPath);
      report.analysisId = id;
      report.filename = safeName;
      await store.saveReport(id, report);
      await store.updateRecord(id, { status: "complete" });
      return textResult({
        analysisId: id,
        filename: safeName,
        notes: notes ?? null,
        fileSizeBytes: bytes.length,
        info: report.info,
        nextSteps: [
          "Call list_functions to browse discovered functions.",
          "Call decompile_function with an exact function address to inspect pseudocode.",
          "Call get_assembly to inspect the captured instruction listing.",
          "Call get_strings to search extracted strings."
        ],
        limitations: "Function and decompilation counts are bounded by server configuration. This is static analysis only."
      });
    } catch (error) {
      if (id) {
        try { await store.updateRecord(id, { status: "failed", error: error instanceof Error ? error.message : String(error) }); } catch { /* preserve original error */ }
      }
      return errorResult(error);
    }
  });

  server.registerTool("list_analyses", {
    description: "List previously submitted binaries and their analysis status.",
    inputSchema: {
      limit: z.number().int().min(1).max(100).optional()
    }
  }, async ({ limit }) => {
    try {
      const records = (await store.list()).slice(0, boundedInteger(limit, 20, 1, 100));
      return textResult(records);
    } catch (error) { return errorResult(error); }
  });

  server.registerTool("get_binary_info", {
    description: "Return binary format, architecture/language, compiler, address range, and analysis counts.",
    inputSchema: { analysisId: z.string().uuid() }
  }, async ({ analysisId }) => {
    try {
      const report = requireReport(await store.getReport(analysisId));
      return textResult({ analysisId, filename: report.filename, analyzedAt: report.analyzedAt, ...report.info });
    } catch (error) { return errorResult(error); }
  });

  server.registerTool("list_functions", {
    description: "List Ghidra-discovered functions. Supports a case-insensitive name filter and pagination.",
    inputSchema: {
      analysisId: z.string().uuid(),
      query: z.string().max(200).optional(),
      offset: z.number().int().min(0).optional(),
      limit: z.number().int().min(1).max(100).optional()
    }
  }, async ({ analysisId, query, offset, limit }) => {
    try {
      const report = requireReport(await store.getReport(analysisId));
      const filtered = query ? report.functions.filter((fn) => fn.name.toLowerCase().includes(query.toLowerCase())) : report.functions;
      const start = boundedInteger(offset, 0, 0, filtered.length);
      const size = boundedInteger(limit, 30, 1, 100);
      return textResult({
        analysisId,
        totalFunctions: report.info.functionCount,
        matchedFunctions: filtered.length,
        offset: start,
        returned: filtered.slice(start, start + size).length,
        functions: filtered.slice(start, start + size).map(({ name, address, size, signature, decompilation }) => ({
          name, address, size, signature, hasDecompilation: Boolean(decompilation)
        }))
      });
    } catch (error) { return errorResult(error); }
  });

  server.registerTool("decompile_function", {
    description: "Retrieve Ghidra decompiler pseudocode for a function. Use an exact function name or address.",
    inputSchema: {
      analysisId: z.string().uuid(),
      function: z.string().min(1).max(300)
    }
  }, async ({ analysisId, function: functionQuery }) => {
    try {
      const report = requireReport(await store.getReport(analysisId));
      const fn = findFunction(report, functionQuery);
      if (!fn.decompilation) throw new Error("No decompilation was saved for this function. It may be outside the configured decompilation cap or unsupported by the decompiler.");
      return textResult({ analysisId, function: fn.name, address: fn.address, signature: fn.signature, pseudocode: fn.decompilation });
    } catch (error) { return errorResult(error); }
  });

  server.registerTool("get_assembly", {
    description: "Retrieve the captured assembly listing for a function. Use an exact function name or address.",
    inputSchema: {
      analysisId: z.string().uuid(),
      function: z.string().min(1).max(300),
      limit: z.number().int().min(1).max(500).optional()
    }
  }, async ({ analysisId, function: functionQuery, limit }) => {
    try {
      const report = requireReport(await store.getReport(analysisId));
      const fn = findFunction(report, functionQuery);
      const instructions = fn.assembly.slice(0, boundedInteger(limit, 160, 1, 500));
      return textResult({ analysisId, function: fn.name, address: fn.address, returned: instructions.length, truncated: instructions.length < fn.assembly.length, assembly: instructions });
    } catch (error) { return errorResult(error); }
  });

  server.registerTool("get_strings", {
    description: "Search strings extracted by Ghidra. Search is case-insensitive and results are paginated.",
    inputSchema: {
      analysisId: z.string().uuid(),
      query: z.string().max(500).optional(),
      offset: z.number().int().min(0).optional(),
      limit: z.number().int().min(1).max(100).optional()
    }
  }, async ({ analysisId, query, offset, limit }) => {
    try {
      const report = requireReport(await store.getReport(analysisId));
      const filtered = query ? report.strings.filter((item) => item.value.toLowerCase().includes(query.toLowerCase())) : report.strings;
      const start = boundedInteger(offset, 0, 0, filtered.length);
      const size = boundedInteger(limit, 40, 1, 100);
      return textResult({ totalStrings: report.info.stringCount, matchedStrings: filtered.length, offset: start, strings: filtered.slice(start, start + size) });
    } catch (error) { return errorResult(error); }
  });

  return server;
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: `${Math.ceil(maxUploadMb * 1.4) + 2}mb` }));

function authenticate(req: Request, res: Response, next: NextFunction) {
  if (!apiKey) {
    if (process.env.NODE_ENV === "production") return res.status(503).json({ error: "Server authentication is not configured." });
    return next();
  }
  const auth = req.header("authorization") ?? "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const supplied = bearer || req.header("x-api-key") || "";
  if (!safeEqualSecret(apiKey, supplied)) return res.status(401).json({ error: "Unauthorized" });
  next();
}

app.get("/", (_req, res) => res.sendFile(path.resolve("public/index.html")));
app.get("/healthz", async (_req, res) => {
  res.json({ status: "ok", service: "rea-mcp", ghidraAvailable: await ghidra.available(), mcpEndpoint: "/mcp" });
});
app.post("/mcp", authenticate, async (req, res) => {
  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => { void transport.close(); void server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    if (!res.headersSent) res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});
app.all("/mcp", (_req, res) => res.status(405).json({ error: "Use POST for Streamable HTTP MCP requests." }));

await store.initialize();
await mkdir(path.join(dataDir, "scripts"), { recursive: true });
const httpServer = app.listen(port, "0.0.0.0", () => {
  console.log(`REA MCP listening on port ${port}; MCP endpoint /mcp`);
});
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    httpServer.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  });
}
