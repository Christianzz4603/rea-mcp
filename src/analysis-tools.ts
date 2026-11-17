import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AnalysisReport } from "./store.js";
import { AnalysisStore } from "./store.js";
import { boundedInteger } from "./validation.js";

function result(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

function fail(error: unknown) {
  return { isError: true, content: [{ type: "text" as const, text: error instanceof Error ? error.message : String(error) }] };
}

async function loadReport(store: AnalysisStore, id: string): Promise<AnalysisReport> {
  const report = await store.getReport(id);
  if (!report) throw new Error("Analysis report not found.");
  return report;
}

function resolveFunction(report: AnalysisReport, query: string) {
  const value = query.trim().toLowerCase();
  const exact = report.functions.find((fn) => fn.address.toLowerCase() === value || fn.name.toLowerCase() === value);
  if (exact) return exact;
  const matches = report.functions.filter((fn) => fn.name.toLowerCase().includes(value));
  if (matches.length === 1 && matches[0]) return matches[0];
  if (matches.length > 1) throw new Error(`Ambiguous function name. Use an exact address. Matches: ${matches.slice(0, 15).map((fn) => `${fn.name} @ ${fn.address}`).join(", ")}`);
  throw new Error(`Function not found: ${query}`);
}

export function registerAnalysisTools(server: McpServer, store: AnalysisStore): void {
  server.registerTool("get_analysis_overview", {
    description: "Get a compact dashboard for an analysis: binary metadata, function/decompilation coverage, strings, and address range.",
    inputSchema: { analysisId: z.string().uuid() }
  }, async ({ analysisId }) => {
    try {
      const report = await loadReport(store, analysisId);
      const externalLooking = report.functions.filter((fn) => fn.name.startsWith("EXTERNAL::")).length;
      return result({
        analysisId, filename: report.filename, analyzedAt: report.analyzedAt,
        binary: report.info,
        coverage: {
          functionsRecorded: report.functions.length,
          decompilationsSaved: report.functions.filter((fn) => Boolean(fn.decompilation)).length,
          functionsWithoutDecompilation: report.functions.filter((fn) => !fn.decompilation).length,
          stringsRecorded: report.strings.length,
          externalLookingFunctions: externalLooking
        },
        capabilities: ["function search", "pseudocode retrieval", "captured assembly search", "string search", "captured call-site discovery"]
      });
    } catch (error) { return fail(error); }
  });

  server.registerTool("search_functions", {
    description: "Search function names, signatures, and saved decompiler pseudocode. Results are paginated.",
    inputSchema: {
      analysisId: z.string().uuid(),
      query: z.string().min(1).max(300),
      offset: z.number().int().min(0).optional(),
      limit: z.number().int().min(1).max(100).optional()
    }
  }, async ({ analysisId, query, offset, limit }) => {
    try {
      const report = await loadReport(store, analysisId);
      const needle = query.toLowerCase();
      const matches = report.functions.filter((fn) =>
        fn.name.toLowerCase().includes(needle) ||
        fn.signature.toLowerCase().includes(needle) ||
        fn.decompilation.toLowerCase().includes(needle)
      );
      const start = boundedInteger(offset, 0, 0, matches.length);
      const size = boundedInteger(limit, 30, 1, 100);
      return result({
        query, totalMatches: matches.length, offset: start,
        functions: matches.slice(start, start + size).map((fn) => ({
          name: fn.name, address: fn.address, size: fn.size, signature: fn.signature,
          hasDecompilation: Boolean(fn.decompilation)
        }))
      });
    } catch (error) { return fail(error); }
  });

  server.registerTool("get_function_summary", {
    description: "Return a consolidated function card containing its signature, address, size, pseudocode availability, and bounded assembly preview.",
    inputSchema: {
      analysisId: z.string().uuid(),
      function: z.string().min(1).max(300),
      assemblyLimit: z.number().int().min(0).max(500).optional()
    }
  }, async ({ analysisId, function: query, assemblyLimit }) => {
    try {
      const report = await loadReport(store, analysisId);
      const fn = resolveFunction(report, query);
      const size = boundedInteger(assemblyLimit, 40, 0, 500);
      return result({
        analysisId, name: fn.name, address: fn.address, size: fn.size, signature: fn.signature,
        hasDecompilation: Boolean(fn.decompilation),
        pseudocode: fn.decompilation || null,
        assembly: fn.assembly.slice(0, size),
        assemblyTruncated: fn.assembly.length > size,
        capturedInstructionCount: fn.assembly.length
      });
    } catch (error) { return fail(error); }
  });

  server.registerTool("get_function_by_address", {
    description: "Resolve an exact address to a discovered function and return its basic metadata.",
    inputSchema: { analysisId: z.string().uuid(), address: z.string().min(1).max(100) }
  }, async ({ analysisId, address }) => {
    try {
      const report = await loadReport(store, analysisId);
      const fn = report.functions.find((item) => item.address.toLowerCase() === address.trim().toLowerCase());
      if (!fn) throw new Error(`No discovered function begins at ${address}.`);
      return result({ name: fn.name, address: fn.address, size: fn.size, signature: fn.signature, hasDecompilation: Boolean(fn.decompilation), capturedInstructions: fn.assembly.length });
    } catch (error) { return fail(error); }
  });

  server.registerTool("find_strings", {
    description: "Search extracted strings by case-insensitive substring. Returns matching addresses and values with pagination.",
    inputSchema: {
      analysisId: z.string().uuid(),
      query: z.string().min(1).max(500),
      offset: z.number().int().min(0).optional(),
      limit: z.number().int().min(1).max(100).optional()
    }
  }, async ({ analysisId, query, offset, limit }) => {
    try {
      const report = await loadReport(store, analysisId);
      const needle = query.toLowerCase();
      const matches = report.strings.filter((item) => item.value.toLowerCase().includes(needle));
      const start = boundedInteger(offset, 0, 0, matches.length);
      const size = boundedInteger(limit, 40, 1, 100);
      return result({ query, totalMatches: matches.length, offset: start, strings: matches.slice(start, start + size) });
    } catch (error) { return fail(error); }
  });

  server.registerTool("search_assembly", {
    description: "Search the assembly lines captured during analysis for a text or mnemonic fragment. Searches only the bounded instructions saved in the report.",
    inputSchema: {
      analysisId: z.string().uuid(),
      query: z.string().min(1).max(200),
      offset: z.number().int().min(0).optional(),
      limit: z.number().int().min(1).max(100).optional()
    }
  }, async ({ analysisId, query, offset, limit }) => {
    try {
      const report = await loadReport(store, analysisId);
      const needle = query.toLowerCase();
      const matches: Array<{ function: string; functionAddress: string; instruction: string }> = [];
      for (const fn of report.functions) {
        for (const instruction of fn.assembly) {
          if (instruction.toLowerCase().includes(needle)) matches.push({ function: fn.name, functionAddress: fn.address, instruction });
        }
      }
      const start = boundedInteger(offset, 0, 0, matches.length);
      const size = boundedInteger(limit, 40, 1, 100);
      return result({ query, totalMatches: matches.length, offset: start, results: matches.slice(start, start + size), note: "Search covers only instructions captured by Ghidra's configured per-function instruction limit." });
    } catch (error) { return fail(error); }
  });

  server.registerTool("find_call_sites", {
    description: "Find call-like instructions in the captured assembly (for example ARM64 BL/BLR or x86 CALL). This is a bounded textual scan, not a complete call graph.",
    inputSchema: {
      analysisId: z.string().uuid(),
      target: z.string().max(200).optional(),
      offset: z.number().int().min(0).optional(),
      limit: z.number().int().min(1).max(100).optional()
    }
  }, async ({ analysisId, target, offset, limit }) => {
    try {
      const report = await loadReport(store, analysisId);
      const callMnemonic = /\b(?:bl|blr|blx|call|callq|jal|jalr)\b/i;
      const needle = target?.toLowerCase();
      const matches: Array<{ function: string; functionAddress: string; instruction: string }> = [];
      for (const fn of report.functions) {
        for (const instruction of fn.assembly) {
          if (callMnemonic.test(instruction) && (!needle || instruction.toLowerCase().includes(needle))) {
            matches.push({ function: fn.name, functionAddress: fn.address, instruction });
          }
        }
      }
      const start = boundedInteger(offset, 0, 0, matches.length);
      const size = boundedInteger(limit, 40, 1, 100);
      return result({ target: target ?? null, totalMatches: matches.length, offset: start, callSites: matches.slice(start, start + size), note: "Only call instructions in the captured assembly window are included; indirect calls and omitted instructions may be absent." });
    } catch (error) { return fail(error); }
  });

  server.registerTool("compare_functions", {
    description: "Retrieve two functions side-by-side for AI-assisted comparison of pseudocode, signatures, sizes, and captured assembly. Does not modify the binary.",
    inputSchema: {
      analysisId: z.string().uuid(),
      functionA: z.string().min(1).max(300),
      functionB: z.string().min(1).max(300),
      assemblyLimit: z.number().int().min(0).max(200).optional()
    }
  }, async ({ analysisId, functionA, functionB, assemblyLimit }) => {
    try {
      const report = await loadReport(store, analysisId);
      const a = resolveFunction(report, functionA);
      const b = resolveFunction(report, functionB);
      const size = boundedInteger(assemblyLimit, 40, 0, 200);
      const card = (fn: typeof a) => ({
        name: fn.name, address: fn.address, size: fn.size, signature: fn.signature,
        pseudocode: fn.decompilation || null,
        assembly: fn.assembly.slice(0, size),
        assemblyTruncated: fn.assembly.length > size
      });
      return result({ analysisId, functionA: card(a), functionB: card(b), comparisonHints: { sameSignature: a.signature === b.signature, sameSize: a.size === b.size } });
    } catch (error) { return fail(error); }
  });
}
