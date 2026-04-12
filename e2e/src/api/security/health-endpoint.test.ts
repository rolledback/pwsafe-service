import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";

describe("Health Endpoint", () => {
  let server: ServerInstance;

  beforeAll(async () => {
    server = new ServerInstance();
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  it("GET /api/health returns 200 with status ok", async () => {
    const resp = await fetch(`${server.baseUrl}/api/health`);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("ok");
  });

  it("health endpoint does not require CSRF token", async () => {
    const resp = await fetch(`${server.baseUrl}/api/health`, {
      headers: {},
    });
    expect(resp.status).toBe(200);
  });

  it("health endpoint returns application/json content type", async () => {
    const resp = await fetch(`${server.baseUrl}/api/health`);
    expect(resp.headers.get("content-type")).toContain("application/json");
  });
});
