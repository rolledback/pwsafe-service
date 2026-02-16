import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const STRICT_RATE_WAIT = 5500;

describe("Auth setup flow", () => {
  describe("disabled setup", () => {
    let server: ServerInstance;
    let api: ApiClient;

    beforeAll(async () => {
      server = new ServerInstance({ skipAuthSetup: true });
      await server.start();
      api = new ApiClient(server.baseUrl, server.csrfToken);
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

    it("setup with disabled mode succeeds", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "disabled" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("ok");
    });

    it("status is disabled after setup", async () => {
      const resp = await api.raw("GET", "/api/auth/status");
      const body = await resp.json();
      expect(body.mode).toBe("disabled");
      expect(body.authenticated).toBe(true);
    });

    it("setup again returns 403", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "disabled" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(403);
    });
  });

  describe("enabled setup", () => {
    let server: ServerInstance;
    let api: ApiClient;

    beforeAll(async () => {
      server = new ServerInstance({ skipAuthSetup: true });
      await server.start();
      api = new ApiClient(server.baseUrl, server.csrfToken);
    });

    afterAll(async () => {
      await server.stop();
    });

    it("setup with enabled mode and password succeeds", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "enabled", password: "mypassword" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(200);
      const body = await resp.json();
      expect(body.status).toBe("ok");
    });

    it("status shows enabled mode, not authenticated", async () => {
      const resp = await api.raw("GET", "/api/auth/status");
      const body = await resp.json();
      expect(body.mode).toBe("enabled");
      expect(body.authenticated).toBe(false);
    });

    it("setup again returns 403", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "enabled", password: "other" }),
        headers: { "Content-Type": "application/json" },
      });
      expect(resp.status).toBe(403);
    });

    it("settings.json omits default auth fields after setup", async () => {
      const raw = await readFile(join(server.configDir, "settings.json"), "utf-8");
      const settings = JSON.parse(raw);
      expect(settings.auth).toBeDefined();
      expect(settings.auth.mode).toBe("enabled");
      // Zero-value fields should be omitted, not written as "" or 0
      expect(settings.auth).not.toHaveProperty("sessionTimeout");
      expect(settings.auth).not.toHaveProperty("bcryptCost");
      expect(settings.auth).not.toHaveProperty("maxSessions");
      expect(settings.auth).not.toHaveProperty("maxSessionLifetime");
    });
  });

  describe("setup edge cases", () => {
    let server: ServerInstance;
    let api: ApiClient;

    beforeAll(async () => {
      server = new ServerInstance({ skipAuthSetup: true });
      await server.start();
      api = new ApiClient(server.baseUrl, server.csrfToken);
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

    it("setup enabled without password returns 400", async () => {
      const resp = await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "enabled" }),
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
      api = new ApiClient(server.baseUrl, server.csrfToken);
    });

    afterAll(async () => {
      await server.stop();
    });

    it("protected endpoints return 503 when mode is unset", async () => {
      const resp = await api.raw("GET", "/api/safes");
      expect(resp.status).toBe(503);
    });

    it("after disabled setup, login endpoint is not needed", async () => {
      await api.raw("POST", "/api/auth/setup", {
        body: JSON.stringify({ mode: "disabled" }),
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
