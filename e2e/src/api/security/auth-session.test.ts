import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// The strict rate limiter allows burst of 2 at 0.2 req/s.
const STRICT_RATE_WAIT = 5500;

describe("Auth session expiry", { timeout: 30_000 }, () => {
  let server: ServerInstance;
  let api: ApiClient;

  beforeAll(async () => {
    server = new ServerInstance({
      authMode: "secured",
      password: "testpass",
      sessionTimeout: "2s",
    });
    await server.start();
    api = new ApiClient(server.baseUrl, server.apiToken);
  });

  afterAll(async () => {
    await server.stop();
  });

  it("after login, immediately access endpoint succeeds", async () => {
    await api.login("testpass");
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.status).toBe(200);
  });

  it("after session timeout, access endpoint returns 401", async () => {
    await sleep(STRICT_RATE_WAIT);
    await api.login("testpass");
    // Wait for session to expire (2s timeout + 1.5s buffer)
    await sleep(3500);
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.status).toBe(401);
  });

  it("activity extends session lifetime", async () => {
    await sleep(STRICT_RATE_WAIT);
    await api.login("testpass");
    // Make requests every 1s for 5 iterations (total ~5s, well past the 2s timeout)
    for (let i = 0; i < 5; i++) {
      await sleep(1000);
      const resp = await api.raw("GET", "/api/safes");
      expect(resp.status).toBe(200);
    }
    // Session should still be valid because activity extends it
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.status).toBe(200);

    // Now stop activity and wait for session to expire
    await sleep(3500); // 2s timeout + 1.5s buffer
    const expiredResp = await api.raw("GET", "/api/safes");
    expect(expiredResp.status).toBe(401);
  });

  it("auth status does not extend session lifetime", async () => {
    await sleep(STRICT_RATE_WAIT);
    await api.login("testpass");

    // Wait 1.5s (within 2s timeout), then hit /api/auth/status
    await sleep(1500);
    const statusResp = await api.raw("GET", "/api/auth/status");
    expect(statusResp.status).toBe(200);
    const body = await statusResp.json();
    expect(body.authenticated).toBe(true);

    // Wait another 1s (total 2.5s since login — past the 2s timeout)
    // If status extended the session, this would still work
    // But it shouldn't extend, so the session should be expired
    await sleep(1000);
    const protectedResp = await api.raw("GET", "/api/safes");
    expect(protectedResp.status).toBe(401);
  });
});
