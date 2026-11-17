import { timingSafeEqual } from "node:crypto";

export function safeFilename(input: string): string {
  const base = input.replace(/\\/g, "/").split("/").pop() ?? "";
  const cleaned = base.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120);
  if (!cleaned || cleaned === "." || cleaned === "..") {
    throw new Error("A valid filename is required.");
  }
  return cleaned;
}

export function decodeBase64(input: string, maxBytes: number): Buffer {
  const compact = input.replace(/\s/g, "");
  if (!compact || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4 !== 0) {
    throw new Error("contentBase64 must be valid standard Base64.");
  }
  const decoded = Buffer.from(compact, "base64");
  const normalizedInput = compact.replace(/=+$/, "");
  const normalizedOutput = decoded.toString("base64").replace(/=+$/, "");
  if (normalizedInput !== normalizedOutput) {
    throw new Error("contentBase64 is malformed.");
  }
  if (decoded.length === 0) throw new Error("The uploaded binary is empty.");
  if (decoded.length > maxBytes) {
    throw new Error(`Upload exceeds the configured limit of ${Math.floor(maxBytes / (1024 * 1024))} MiB.`);
  }
  return decoded;
}

export function safeEqualSecret(expected: string, supplied: string): boolean {
  const left = Buffer.from(expected);
  const right = Buffer.from(supplied);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function boundedInteger(value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(value)));
}
