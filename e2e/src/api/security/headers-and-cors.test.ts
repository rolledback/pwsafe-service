import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

describe("Headers and CORS", () => {
  let server: ServerInstance;
  let api: ApiClient;

  beforeAll(async () => {
    server = new ServerInstance();
    await server.start();
    api = new ApiClient(server.baseUrl, server.apiToken);
  });

  afterAll(async () => {
    await server.stop();
  });

  it("API response does NOT contain Access-Control-Allow-Origin", async () => {
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("response contains X-Content-Type-Options: nosniff", async () => {
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("response contains X-Frame-Options: DENY", async () => {
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.headers.get("x-frame-options")).toBe("DENY");
  });

  it("response contains Referrer-Policy: no-referrer", async () => {
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("GET /web/ contains Content-Security-Policy with nonce (not unsafe-inline)", async () => {
    const resp = await api.raw("GET", "/web/", { token: null });
    const csp = resp.headers.get("content-security-policy");
    expect(csp).toBeTruthy();
    expect(csp).toContain("'nonce-");
    expect(csp).not.toContain("'unsafe-inline'");
  });

  it("successive /web/ requests have different CSP nonces", async () => {
    const resp1 = await api.raw("GET", "/web/", { token: null });
    const resp2 = await api.raw("GET", "/web/", { token: null });

    const csp1 = resp1.headers.get("content-security-policy")!;
    const csp2 = resp2.headers.get("content-security-policy")!;

    const nonceRegex = /'nonce-([^']+)'/;
    const nonce1 = csp1.match(nonceRegex)?.[1];
    const nonce2 = csp2.match(nonceRegex)?.[1];

    expect(nonce1).toBeTruthy();
    expect(nonce2).toBeTruthy();
    expect(nonce1).not.toBe(nonce2);
  });
});
