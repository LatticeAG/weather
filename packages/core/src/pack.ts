import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { D, H } from "./hash.js";
import type { PackManifest } from "./types.js";

/**
 * Pack manifest (§3.2): pack_digest = D("WEATHER-PACK/1", PackManifest).
 * corpus_digest = D("WEATHER-CORPUS/1", {v:1, vectors:Vs, fixtures:Fs}) where
 * Vs is the §13 vector objects in TV-W--01..60 order and Fs the §6.2 printed
 * fixture lines. artifact_digest = D("WEATHER-ARTIFACT/1", {v:1, files:Fa})
 * over every released core module sorted by path, excluding the manifest
 * file itself and mutable package labels.
 */

export function corpusDigest(vectors: unknown[], fixtureLines: string[]): string {
  return D("WEATHER-CORPUS/1", { v: 1, vectors, fixtures: fixtureLines });
}

export function artifactDigest(files: { path: string; sha256: string }[]): string {
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return D("WEATHER-ARTIFACT/1", { v: 1, files: sorted });
}

export function packDigest(manifest: PackManifest): string {
  return D("WEATHER-PACK/1", manifest);
}

function listFiles(root: string, dir: string, out: string[]): void {
  for (const e of readdirSync(join(root, dir), { withFileTypes: true })) {
    const rel = join(dir, e.name);
    if (e.isDirectory()) listFiles(root, rel, out);
    else if (e.isFile() && e.name.endsWith(".ts")) out.push(rel);
  }
}

/**
 * Build the installed pack manifest for this release tree. `coreDirs` lists
 * the released core module directories per language (source .ts/.py files);
 * the PackManifest file itself is excluded by construction.
 */
export function buildPackManifest(opts: {
  repoRoot: string;
  vectors: unknown[];
  fixtureLines: string[];
}): PackManifest {
  const files: { language: "typescript" | "python"; list: { path: string; sha256: string }[] }[] = [
    { language: "typescript", list: [] },
    { language: "python", list: [] },
  ];
  const tsFiles: string[] = [];
  listFiles(opts.repoRoot, "packages/core/src", tsFiles);
  for (const rel of tsFiles.sort()) {
    const p = join(opts.repoRoot, rel);
    files[0]!.list.push({ path: rel.split("\\").join("/"), sha256: H(readFileSync(p)) });
  }
  const pyDir = join(opts.repoRoot, "python/lattice_weather");
  for (const name of readdirSync(pyDir).filter((n) => n.endsWith(".py")).sort()) {
    const p = join(pyDir, name);
    if (!statSync(p).isFile()) continue;
    files[1]!.list.push({ path: `python/lattice_weather/${name}`, sha256: H(readFileSync(p)) });
  }
  return {
    v: 1,
    pack: "weather-core/1.0.0",
    schema_major: 1,
    semantics: "WEATHER-SPEC-2026-09-12/4.3",
    corpus_digest: corpusDigest(opts.vectors, opts.fixtureLines),
    implementations: files
      .map((f) => ({ language: f.language, artifact_digest: artifactDigest(f.list) }))
      .sort((a, b) => (a.language < b.language ? -1 : 1)),
  };
}
