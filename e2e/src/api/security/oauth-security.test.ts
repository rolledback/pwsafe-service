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
});
