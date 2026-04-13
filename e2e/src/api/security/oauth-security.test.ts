import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

describe("OAuth Security", () => {
  let server: ServerInstance;
  let api: ApiClient;

  beforeAll(async () => {
    server = new ServerInstance();
    await server.start();
    api = new ApiClient(server.baseUrl, server.csrfToken);
  });

  afterAll(async () => {
    await server.stop();
  });

  it("OAuth callback is exempt from token requirement (returns 302, not 403)", async () => {
    const resp = await api.raw("GET", "/api/providers/mock/auth/callback?code=test", { csrfToken: null });
    expect(resp.status).toBe(302);
  });

  it("OAuth callback redirects to /web/add/{provider}", async () => {
    const resp = await api.raw("GET", "/api/providers/mock/auth/callback?code=test", { csrfToken: null });
    expect(resp.status).toBe(302);
    const location = resp.headers.get("location");
    expect(location).toContain("/web/add/mock");
  });

  it("configured and unconfigured providers return same status on callback", async () => {
    const configuredResp = await api.raw("GET", "/api/providers/mock/auth/callback?code=test", { csrfToken: null });
    const unconfiguredResp = await api.raw("GET", "/api/providers/nonexistent/auth/callback?code=test", { csrfToken: null });
    expect(configuredResp.status).toBe(302);
    expect(unconfiguredResp.status).toBe(302);
  });

  it("unconfigured provider callback uses generic error parameter", async () => {
    const resp = await api.raw("GET", "/api/providers/nonexistent/auth/callback?code=test", { csrfToken: null });
    const location = resp.headers.get("location");
    expect(location).toContain("error=auth_error");
    // Should not leak specific error details
    expect(location).not.toContain("token_exchange_failed");
    expect(location).not.toContain("not_found");
  });

  it("configured provider callback with missing code uses generic error", async () => {
    const resp = await api.raw("GET", "/api/providers/mock/auth/callback", { csrfToken: null });
    expect(resp.status).toBe(302);
    const location = resp.headers.get("location");
    expect(location).toContain("error=auth_error");
    // Should not leak "auth_failed" or other specific errors
    expect(location).not.toContain("auth_failed");
  });

  it("POST to callback returns same status for configured and unconfigured providers", async () => {
    const configuredResp = await api.raw("POST", "/api/providers/mock/auth/callback", { csrfToken: null });
    const unconfiguredResp = await api.raw("POST", "/api/providers/nonexistent/auth/callback", { csrfToken: null });
    expect(configuredResp.status).toBe(unconfiguredResp.status);
  });
});
