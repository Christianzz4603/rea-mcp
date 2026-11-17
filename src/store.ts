import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";

export interface AnalysisRecord {
  id: string;
  filename: string;
  createdAt: string;
  status: "running" | "complete" | "failed";
  error?: string;
}

export interface AnalysisReport {
  analysisId: string;
  filename: string;
  analyzedAt: string;
  info: {
    format: string;
    language: string;
    compiler: string;
    executablePath: string;
    minAddress: string;
    maxAddress: string;
    functionCount: number;
    decompiledCount: number;
    stringCount: number;
  };
  functions: Array<{
    name: string;
    address: string;
    size: number;
    signature: string;
    decompilation: string;
    assembly: string[];
  }>;
  strings: Array<{ address: string; value: string }>;
}

export class AnalysisStore {
  readonly root: string;

  constructor(root: string) {
    this.root = path.resolve(root);
  }

  async initialize(): Promise<void> {
    await mkdir(path.join(this.root, "analyses"), { recursive: true });
    await mkdir(path.join(this.root, "projects"), { recursive: true });
    await mkdir(path.join(this.root, "scripts"), { recursive: true });
  }

  newId(): string {
    return randomUUID();
  }

  directory(id: string): string {
    if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error("Invalid analysis ID.");
    return path.join(this.root, "analyses", id);
  }

  async createRecord(record: AnalysisRecord): Promise<void> {
    const dir = this.directory(record.id);
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(dir, "record.json"), JSON.stringify(record, null, 2), "utf8");
  }

  async updateRecord(id: string, patch: Partial<AnalysisRecord>): Promise<void> {
    const current = await this.getRecord(id);
    await writeFile(path.join(this.directory(id), "record.json"), JSON.stringify({ ...current, ...patch }, null, 2), "utf8");
  }

  async getRecord(id: string): Promise<AnalysisRecord> {
    return JSON.parse(await readFile(path.join(this.directory(id), "record.json"), "utf8")) as AnalysisRecord;
  }

  async saveReport(id: string, report: AnalysisReport): Promise<void> {
    await writeFile(path.join(this.directory(id), "report.json"), JSON.stringify(report), "utf8");
  }

  async getReport(id: string): Promise<AnalysisReport> {
    return JSON.parse(await readFile(path.join(this.directory(id), "report.json"), "utf8")) as AnalysisReport;
  }

  async list(): Promise<AnalysisRecord[]> {
    const base = path.join(this.root, "analyses");
    const entries = await readdir(base, { withFileTypes: true });
    const records: AnalysisRecord[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory() || !/^[0-9a-f-]{36}$/i.test(entry.name)) continue;
      try {
        const record = await this.getRecord(entry.name);
        records.push(record);
      } catch {
        // Ignore incomplete records left by an interrupted upload.
      }
    }
    return records.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async inputPath(id: string): Promise<string> {
    const dir = this.directory(id);
    await stat(dir);
    return path.join(dir, "input.bin");
  }

  projectPath(id: string): string {
    return path.join(this.root, "projects", id);
  }

  scriptPath(): string {
    return path.resolve(process.cwd(), "ghidra_scripts");
  }
}
