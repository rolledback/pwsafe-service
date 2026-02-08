import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const TESTDATA_DIR = resolve(import.meta.dirname, "..", "..", "..", "backend", "testdata");

export async function loadTestSafe(name: string): Promise<Buffer> {
  return readFile(join(TESTDATA_DIR, name));
}
