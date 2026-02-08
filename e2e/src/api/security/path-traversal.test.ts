import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

describe("Path Traversal Protection", () => {
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

  it("PUT mock files with traversal path is rejected", async () => {
    const resp = await api.raw("PUT", "/api/providers/mock/files", {
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        files: [
          {
            id: "simple.psafe3",
            name: "evil.txt",
            path: "../../../../",
            selected: true,
          },
        ],
      }),
    });
    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toContain("traversal");
  });

  it("PUT mock files with traversal path does not persist to config", async () => {
    // Connect the mock provider first
    const authUrlResp = await api.getProviderAuthUrl("mock");
    await api.raw("GET", new URL(authUrlResp.url).pathname + new URL(authUrlResp.url).search);

    // Attempt the bad PUT (should be rejected)
    await api.raw("PUT", "/api/providers/mock/files", {
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        files: [
          {
            id: "simple.psafe3",
            name: "evil.txt",
            path: "../../../../",
            selected: true,
          },
        ],
      }),
    });

    // Sync should have nothing to sync (bad files were never saved)
    const syncResp = await api.raw("POST", "/api/providers/mock/sync");
    const syncBody = await syncResp.json();
    const results = syncBody.results || [];
    const traversalResult = results.find((r: any) => r.name === "evil.txt");
    expect(traversalResult).toBeUndefined();
  }, 15000);

  it("DELETE with traversal-like ID returns 404 (ID-based, no path exposure)", async () => {
    const resp = await api.raw("DELETE", "/api/providers/static/files/..%2F..%2Ftest");
    expect(resp.status).toBe(404);
    const body = await resp.json();
    expect(body.error).toBeTruthy();
  });

  it("/web/ path traversal does not leak file contents", async () => {
    const resp = await api.raw("GET", "/web/..%2F..%2Fbackend/go.mod", { token: null });
    const body = await resp.text();
    expect(body).not.toContain("module github.com");
  });

  it("/web/ nonexistent path serves SPA fallback", async () => {
    const resp = await api.raw("GET", "/web/nonexistent-page", { token: null });
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain("</html>");
  });

  const traversalPatterns = ["..%2F", "..%252F"];

  for (const pattern of traversalPatterns) {
    it(`/web/ traversal pattern "${pattern}" does not leak files`, async () => {
      const resp = await api.raw("GET", `/web/${pattern}${pattern}backend/go.mod`, { token: null });
      const body = await resp.text();
      expect(body).not.toContain("module github.com");
    });
  }
});
