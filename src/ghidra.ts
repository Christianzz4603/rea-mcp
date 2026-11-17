import { spawn } from "node:child_process";
import { access, copyFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { AnalysisReport } from "./store.js";
import { AnalysisStore } from "./store.js";

interface GhidraConfig {
  home: string;
  timeoutMs: number;
  maxFunctions: number;
  maxDecompiles: number;
  maxStrings: number;
  maxInstructions: number;
}

function run(command: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], env: process.env });
    let stdout = "";
    let stderr = "";
    const append = (current: string, chunk: Buffer) => (current + chunk.toString("utf8")).slice(-12000);
    child.stdout.on("data", (chunk: Buffer) => { stdout = append(stdout, chunk); });
    child.stderr.on("data", (chunk: Buffer) => { stderr = append(stderr, chunk); });
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 5000).unref();
      reject(new Error(`Ghidra analysis exceeded ${Math.round(timeoutMs / 1000)} seconds. ${stderr.slice(-3000)}`));
    }, timeoutMs);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(new Error(`Could not start Ghidra: ${error.message}`));
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`Ghidra exited with code ${code}.\n${stderr.slice(-6000)}\n${stdout.slice(-2000)}`));
      } else {
        resolve(stdout + (stderr ? `\n${stderr}` : ""));
      }
    });
  });
}

export class GhidraRunner {
  private readonly config: GhidraConfig;
  private readonly store: AnalysisStore;
  private running = false;

  constructor(store: AnalysisStore) {
    this.store = store;
    const home = path.resolve(process.env.GHIDRA_HOME ?? "/opt/ghidra");
    this.config = {
      home,
      timeoutMs: Number(process.env.ANALYSIS_TIMEOUT_MS ?? 900000),
      maxFunctions: Number(process.env.MAX_FUNCTIONS ?? 2500),
      maxDecompiles: Number(process.env.MAX_DECOMPILES ?? 250),
      maxStrings: Number(process.env.MAX_STRINGS ?? 10000),
      maxInstructions: Number(process.env.MAX_INSTRUCTIONS_PER_FUNCTION ?? 160)
    };
  }

  async available(): Promise<boolean> {
    try {
      await access(path.join(this.config.home, "support", "analyzeHeadless"));
      return true;
    } catch {
      return false;
    }
  }

  async analyze(id: string, inputPath: string): Promise<AnalysisReport> {
    if (this.running) throw new Error("The Ghidra worker is busy. Try again after the current analysis finishes.");
    this.running = true;
    try {
      const executable = path.join(this.config.home, "support", "analyzeHeadless");
      const scriptSource = path.join(this.store.scriptPath(), "ExportAnalysis.java");
      const scriptTarget = path.join(this.store.root, "scripts", "ExportAnalysis.java");
      await copyFile(scriptSource, scriptTarget);
      const outputPath = path.join(this.store.directory(id), "report.json");
      const projectPath = this.store.projectPath(id);
      await mkdir(projectPath, { recursive: true });
      const args = [
        projectPath,
        "project",
        "-import", inputPath,
        "-overwrite",
        "-scriptPath", path.dirname(scriptTarget),
        "-postScript", "ExportAnalysis.java",
        outputPath,
        String(this.config.maxFunctions),
        String(this.config.maxDecompiles),
        String(this.config.maxStrings),
        String(this.config.maxInstructions)
      ];
      await run(executable, args, this.config.timeoutMs);
      return JSON.parse(await readFile(outputPath, "utf8")) as AnalysisReport;
    } finally {
      this.running = false;
    }
  }
}
