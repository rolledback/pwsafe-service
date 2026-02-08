import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

describe("Token Authentication Enforcement", () => {
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

  const getEndpoints = ["/api/safes", "/api/providers", "/api/providers/mock/status", "/api/providers/mock/files"];

  const mutatingEndpoints: Array<{ method: string; path: string }> = [
    { method: "POST", path: "/api/safes/nonexistent/unlock" },
    { method: "POST", path: "/api/providers/mock/sync" },
    { method: "PUT", path: "/api/providers/mock/files" },
  ];

  describe("requests without token return 403", () => {
    for (const path of getEndpoints) {
      it(`GET ${path} → 403`, async () => {
        const resp = await api.raw("GET", path, { token: null });
        expect(resp.status).toBe(403);
      });
    }

    for (const { method, path } of mutatingEndpoints) {
      it(`${method} ${path} → 403`, async () => {
        const resp = await api.raw(method, path, { token: null });
        expect(resp.status).toBe(403);
      });
    }
  });

  describe("requests with wrong token return 403", () => {
    for (const path of getEndpoints) {
      it(`GET ${path} → 403`, async () => {
        const resp = await api.raw("GET", path, { token: "badtoken" });
        expect(resp.status).toBe(403);
      });
    }

    for (const { method, path } of mutatingEndpoints) {
      it(`${method} ${path} → 403`, async () => {
        const resp = await api.raw(method, path, { token: "badtoken" });
        expect(resp.status).toBe(403);
      });
    }
  });

  describe("requests with correct token do not return 403", () => {
    for (const path of getEndpoints) {
      it(`GET ${path} → not 403`, async () => {
        const resp = await api.raw("GET", path);
        expect(resp.status).not.toBe(403);
      });
    }

    for (const { method, path } of mutatingEndpoints) {
      it(`${method} ${path} → not 403`, async () => {
        const resp = await api.raw(method, path, {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });
        expect(resp.status).not.toBe(403);
      });
    }
  });
});
