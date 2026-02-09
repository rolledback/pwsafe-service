import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const STRICT_RATE_WAIT = 5500;

describe("IP banning", { timeout: 60_000 }, () => {
  let server: ServerInstance;
  let api: ApiClient;

  beforeAll(async () => {
    server = new ServerInstance({ authMode: "secured", password: "testpass" });
    await server.start();
    api = new ApiClient(server.baseUrl, server.apiToken);
  });

  afterAll(async () => {
    await server.stop();
  });

  it("bans IP after 5 failed login attempts", async () => {
    for (let i = 0; i < 5; i++) {
      if (i >= 1) await sleep(STRICT_RATE_WAIT);
      const resp = await api.raw("POST", "/api/auth/login", {
        body: JSON.stringify({ password: "wrong" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(401);
    }

    // Now the IP should be banned
    await sleep(STRICT_RATE_WAIT);
    const bannedResp = await api.raw("POST", "/api/auth/login", {
      body: JSON.stringify({ password: "testpass" }),
      headers: { "Content-Type": "application/json" },
    });
    expect(bannedResp.status).toBe(403);

    // Protected endpoints also blocked
    const protectedResp = await api.raw("GET", "/api/safes");
    expect(protectedResp.status).toBe(403);
  });
});
