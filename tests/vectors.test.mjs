import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { runKernel } from "../packages/core/dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(readFileSync(join(root, "conformance/vectors.json"), "utf8"));

function deep(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deep(x, b[i]));
  }
  if (typeof a === "object") {
    const ka = Object.keys(a), kb = Object.keys(b);
    return ka.length === kb.length && ka.every((k) => deep(a[k], b[k]));
  }
  return false;
}

for (const v of vectors) {
  test(`${v.id}`, () => {
    const out = runKernel(v.input);
    assert.ok(deep(out, v.expected), `${v.id}: got ${JSON.stringify(out)} want ${JSON.stringify(v.expected)}`);
  });
}
