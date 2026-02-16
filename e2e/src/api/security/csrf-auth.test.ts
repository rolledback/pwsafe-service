import { describe, it, expect } from "vitest";
import { describeDualMode } from "../../helpers/dual-mode";

describeDualMode("CSRF Token Authentication", {}, (getApi) => {
  const getEndpoints = ["/api/safes", "/api/providers", "/api/providers/mock/status", "/api/providers/mock/files"];

  const mutatingEndpoints: Array<{ method: string; path: string }> = [
    { method: "POST", path: "/api/safes/nonexistent/unlock" },
    { method: "POST", path: "/api/providers/mock/sync" },
    { method: "PUT", path: "/api/providers/mock/files" },
  ];

  describe("requests without token return 403", () => {
    for (const path of getEndpoints) {
      it(`GET ${path} → 403`, async () => {
        const api = getApi();
        const resp = await api.raw("GET", path, { csrfToken: null });
        expect(resp.status).toBe(403);
      });
    }

    for (const { method, path } of mutatingEndpoints) {
      it(`${method} ${path} → 403`, async () => {
        const api = getApi();
        const resp = await api.raw(method, path, { csrfToken: null });
        expect(resp.status).toBe(403);
      });
    }
  });

  describe("requests with wrong token return 403", () => {
    for (const path of getEndpoints) {
      it(`GET ${path} → 403`, async () => {
        const api = getApi();
        const resp = await api.raw("GET", path, { csrfToken: "badtoken" });
        expect(resp.status).toBe(403);
      });
    }

    for (const { method, path } of mutatingEndpoints) {
      it(`${method} ${path} → 403`, async () => {
        const api = getApi();
        const resp = await api.raw(method, path, { csrfToken: "badtoken" });
        expect(resp.status).toBe(403);
      });
    }
  });

  describe("requests with correct token do not return 403", () => {
    for (const path of getEndpoints) {
      it(`GET ${path} → not 403`, async () => {
        const api = getApi();
        const resp = await api.raw("GET", path);
        expect(resp.status).toBeGreaterThanOrEqual(200);
        expect(resp.status).toBeLessThan(400);
      });
    }

    for (const { method, path } of mutatingEndpoints) {
      it(`${method} ${path} → not 403`, async () => {
        const api = getApi();
        const resp = await api.raw(method, path, {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });
        // These hit nonexistent/disconnected resources so may return 4xx/5xx,
        // but should NOT return 403 (which would mean token was rejected)
        expect(resp.status).not.toBe(403);
      });
    }
  });
});
