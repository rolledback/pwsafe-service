import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// The strict rate limiter allows burst of 2 at 0.2 req/s.
const STRICT_RATE_WAIT = 5500;

describe("Auth login and logout", () => {
  let server: ServerInstance;
  let api: ApiClient;

  beforeAll(async () => {
    server = new ServerInstance({ authMode: "enabled", password: "testpass" });
    await server.start();
    api = new ApiClient(server.baseUrl, server.csrfToken);
  });

  afterAll(async () => {
    await server.stop();
  });

  it("login with correct password succeeds", async () => {
    const resp = await api.raw("POST", "/api/auth/login", {
      body: JSON.stringify({ password: "testpass" }),
      headers: { "Content-Type": "application/json" },
    });
    expect(resp.status).toBe(200);
    const setCookie = resp.headers.get("set-cookie");
    expect(setCookie).toBeTruthy();
    expect(setCookie).toContain("pwsafe_session_id=");
  });

  it("login with wrong password fails", async () => {
    await sleep(STRICT_RATE_WAIT);
    const resp = await api.raw("POST", "/api/auth/login", {
      body: JSON.stringify({ password: "wrongpass" }),
      headers: { "Content-Type": "application/json" },
    });
    expect(resp.status).toBe(401);
  });

  it("after login, protected endpoints return 200", async () => {
    await sleep(STRICT_RATE_WAIT);
    await api.login("testpass");
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body)).toBe(true);
  });

  it("after logout, protected endpoints return 401", async () => {
    await api.logout();
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.status).toBe(401);
  });

  it("login again after logout works", async () => {
    await sleep(STRICT_RATE_WAIT);
    await api.login("testpass");
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body)).toBe(true);
  });

  it("auth status shows authenticated after login", async () => {
    await sleep(STRICT_RATE_WAIT);
    await api.login("testpass");
    const resp = await api.raw("GET", "/api/auth/status");
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.mode).toBe("enabled");
    expect(body.authenticated).toBe(true);
  });

  it("re-login invalidates prior session", async () => {
    await sleep(STRICT_RATE_WAIT);
    await api.login("testpass");

    // Save current session cookie
    const firstSessionResp = await api.raw("GET", "/api/safes");
    expect(firstSessionResp.status).toBe(200);

    // Create a second client that will hold the first session's cookie
    const api2 = new ApiClient(server.baseUrl, server.csrfToken);
    (api2 as any).cookies["pwsafe_session_id"] = (api as any).cookies["pwsafe_session_id"];

    // Login again with the main client (invalidates old session from same IP)
    await sleep(STRICT_RATE_WAIT);
    await api.login("testpass");

    // Old session (in api2) should now be invalid
    const resp = await api2.raw("GET", "/api/safes");
    expect(resp.status).toBe(401);
  });

  it("logout without session cookie returns 401", async () => {
    // Create a fresh client with no cookies
    const freshApi = new ApiClient(server.baseUrl, server.csrfToken);
    const resp = await freshApi.raw("POST", "/api/auth/logout");
    expect(resp.status).toBe(401);
  });

  it("malformed session cookie returns 401 not 500", async () => {
    // Create a client and manually set a garbage cookie
    const badApi = new ApiClient(server.baseUrl, server.csrfToken);
    (badApi as any).cookies["pwsafe_session_id"] = "not-valid-hex!!!garbage";
    const resp = await badApi.raw("GET", "/api/safes");
    expect(resp.status).toBe(401);
  });
});
