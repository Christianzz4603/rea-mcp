import test from "node:test";
import assert from "node:assert/strict";
import { boundedInteger, decodeBase64, safeEqualSecret, safeFilename } from "./validation.js";

test("safeFilename strips directories and unsafe characters", () => {
  assert.equal(safeFilename("../../libminecraftpe.so"), "libminecraftpe.so");
  assert.equal(safeFilename("folder\\evil name.so"), "evil_name.so");
  assert.throws(() => safeFilename("../.."));
});

test("decodeBase64 validates and enforces byte limits", () => {
  assert.deepEqual(decodeBase64(Buffer.from("ELF").toString("base64"), 10), Buffer.from("ELF"));
  assert.throws(() => decodeBase64("not base64!", 100));
  assert.throws(() => decodeBase64(Buffer.from("too big").toString("base64"), 2));
  assert.throws(() => decodeBase64("", 100));
});

test("secret comparison handles matching and non-matching values", () => {
  assert.equal(safeEqualSecret("secret", "secret"), true);
  assert.equal(safeEqualSecret("secret", "other"), false);
});

test("boundedInteger clamps values", () => {
  assert.equal(boundedInteger(undefined, 10, 1, 20), 10);
  assert.equal(boundedInteger(100, 10, 1, 20), 20);
  assert.equal(boundedInteger(-1, 10, 1, 20), 1);
});
