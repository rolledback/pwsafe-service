import { it, expect } from "vitest";
import { describeDualMode } from "../../helpers/dual-mode";
import type { SafeFile } from "../../../../frontend/src/api/client";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const STRICT_RATE_WAIT = 5500;

describeDualMode("Body Size Limits", {}, (getApi) => {
  let safeId: string;

  it("find a test safe for body limit tests", async () => {
    const api = getApi();
    const safes = await api.listSafes();
    const safe = safes.find((s: SafeFile) => s.name === "simple.psafe3");
    expect(safe).toBeDefined();
    safeId = safe!.id;
  });

  it("rejects oversized body on POST /api/safes/:id/unlock", async () => {
    const api = getApi();
    await sleep(STRICT_RATE_WAIT);
    const oversizedPassword = "a".repeat(2000);
    const resp = await api.raw("POST", `/api/safes/${safeId}/unlock`, {
      body: JSON.stringify({ password: oversizedPassword }),
      headers: { "Content-Type": "application/json" },
    });
    expect(resp.status).toBe(413);
    const body = await resp.json();
    expect(body.error).toContain("too large");
  });

  it("rejects oversized body on POST /api/safes/:id/entry", async () => {
    const api = getApi();
    await sleep(STRICT_RATE_WAIT);
    const oversizedPassword = "a".repeat(2000);
    const resp = await api.raw("POST", `/api/safes/${safeId}/entry`, {
      body: JSON.stringify({ password: oversizedPassword, entryUuid: "00000000-0000-0000-0000-000000000000" }),
      headers: { "Content-Type": "application/json" },
    });
    expect(resp.status).toBe(413);
    const body = await resp.json();
    expect(body.error).toContain("too large");
  });

  it("rejects oversized body on PUT /api/providers/:id/files", async () => {
    const api = getApi();
    // Build a valid JSON payload that exceeds 8KB
    const oversizedFiles = Array.from({ length: 50 }, (_, i) => ({
      id: "a".repeat(200),
      name: `file-${i}.psafe3`,
    }));
    const resp = await api.raw("PUT", "/api/providers/mock/files", {
      body: JSON.stringify({ files: oversizedFiles }),
      headers: { "Content-Type": "application/json" },
    });
    expect(resp.status).toBe(413);
    const body = await resp.json();
    expect(body.error).toContain("too large");
  });

  it("accepts normal-sized body on POST /api/safes/:id/unlock", async () => {
    const api = getApi();
    await sleep(STRICT_RATE_WAIT);
    const resp = await api.raw("POST", `/api/safes/${safeId}/unlock`, {
      body: JSON.stringify({ password: "short" }),
      headers: { "Content-Type": "application/json" },
    });
    // Should not be 413 — may be 401 (wrong password) but not body-too-large
    expect(resp.status).not.toBe(413);
  });
});
