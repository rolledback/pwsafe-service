import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

describe("Upload Validation", () => {
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

  it("rejects upload with .txt extension", async () => {
    const content = Buffer.from("fake content");
    const resp = await api.uploadStaticSafe("test.txt", content);
    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toContain(".psafe3");
  });

  it("accepts upload with .psafe3 extension", async () => {
    const content = Buffer.from("fake psafe3 content");
    const resp = await api.uploadStaticSafe("test-upload.psafe3", content);
    // Should succeed (200) or conflict (409 if already exists)
    expect([200, 409]).toContain(resp.status);
  });

  it("rejects upload with no extension", async () => {
    const content = Buffer.from("fake content");
    const resp = await api.uploadStaticSafe("noextension", content);
    expect(resp.status).toBe(400);
  });

  it("rejects upload with .psafe3.txt double extension", async () => {
    const content = Buffer.from("fake content");
    const resp = await api.uploadStaticSafe("test.psafe3.txt", content);
    expect(resp.status).toBe(400);
  });
});
