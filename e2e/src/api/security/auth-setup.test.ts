import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const STRICT_RATE_WAIT = 5500;

describe("Auth setup flow", () => {
  describe("unsecured setup", () => {
    let server: ServerInstance;
    let api: ApiClient;

    beforeAll(async () => {
      server = new ServerInstance({ skipAuthSetup: true });
      await server.start();
      api = new ApiClient(server.baseUrl, server.apiToken);
    });

    afterAll(async () => {
      await server.stop();
    });

    it("initial status is unset", async () => {
      const resp = await api.raw("GET", "/api/auth/status");
      expect(resp.status).toBe(200);
      const body = await resp.json();
      expect(body.mode).toBe("unset");
    });

    it("setup with unsecured mode succeeds", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "unsecured" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("ok");
    });

    it("status is unsecured after setup", async () => {
      const resp = await api.raw("GET", "/api/auth/status");
      const body = await resp.json();
      expect(body.mode).toBe("unsecured");
      expect(body.authenticated).toBe(true);
    });

    it("setup again returns 403", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "unsecured" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(403);
    });
  });

  describe("secured setup", () => {
    let server: ServerInstance;
    let api: ApiClient;

    beforeAll(async () => {
      server = new ServerInstance({ skipAuthSetup: true });
      await server.start();
      api = new ApiClient(server.baseUrl, server.apiToken);
    });

    afterAll(async () => {
      await server.stop();
    });

    it("setup with secured mode and password succeeds", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "secured", password: "mypassword" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("ok");
    });

    it("status shows secured mode, not authenticated", async () => {
      const resp = await api.raw("GET", "/api/auth/status");
      const body = await resp.json();
      expect(body.mode).toBe("secured");
      expect(body.authenticated).toBe(false);
    });

    it("setup again returns 403", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "secured", password: "other" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(403);
    });
  });

  describe("setup edge cases", () => {
    let server: ServerInstance;
    let api: ApiClient;

    beforeAll(async () => {
      server = new ServerInstance({ skipAuthSetup: true });
      await server.start();
      api = new ApiClient(server.baseUrl, server.apiToken);
    });

    afterAll(async () => {
      await server.stop();
    });

    it("setup with invalid mode returns 400", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "bogus" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(400);
    });

    it("setup secured without password returns 400", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "secured" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(400);
    });

    it("setup with malformed JSON returns 400", async () => {
      await sleep(STRICT_RATE_WAIT);
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: "{invalid json",
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(400);
    });

    it("GET on setup endpoint returns 405", async () => {
      await sleep(STRICT_RATE_WAIT);
      const resp = await api.raw("GET", "/api/auth/setup");
      expect(resp.status).toBe(405);
    });
  });

  describe("mode behavior", () => {
    let server: ServerInstance;
    let api: ApiClient;

    beforeAll(async () => {
      server = new ServerInstance({ skipAuthSetup: true });
      await server.start();
      api = new ApiClient(server.baseUrl, server.apiToken);
    });

    afterAll(async () => {
      await server.stop();
    });

    it("protected endpoints return 503 when mode is unset", async () => {
      const resp = await api.raw("GET", "/api/safes");
      expect(resp.status).toBe(503);
    });

    it("after unsecured setup, login endpoint is not needed", async () => {
      await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "unsecured" }),
        headers: { "Content-Type": "application/json" },
      });
      // Protected endpoints should work without login
      const resp = await api.raw("GET", "/api/safes");
      expect(resp.status).toBe(200);
      const body = await resp.json();
      expect(Array.isArray(body)).toBe(true);
    });
  });
});
