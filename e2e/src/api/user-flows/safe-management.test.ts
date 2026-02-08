import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";
import { loadTestSafe } from "../../helpers/fixtures";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("Safe upload and delete management", () => {
  let server: ServerInstance;
  let api: ApiClient;

  const uploadName = "uploaded-test.psafe3";

  beforeAll(async () => {
    server = new ServerInstance();
    await server.start();
    api = new ApiClient(server.baseUrl, server.apiToken);
  });

  afterAll(async () => {
    await server.stop();
  });

  it("uploads a safe file and it appears in the safe list", async () => {
    const content = await loadTestSafe("simple.psafe3");
    const resp = await api.uploadStaticSafe(uploadName, content);

    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.success).toBe(true);
    expect(body.name).toBe(uploadName);

    const safes = await api.listSafes();
    const names = safes.map((s) => s.name);
    expect(names).toContain(uploadName);
  });

  it("returns 409 when uploading a duplicate filename", async () => {
    const content = await loadTestSafe("simple.psafe3");
    const resp = await api.uploadStaticSafe(uploadName, content);

    expect(resp.status).toBe(409);
    const body = await resp.json();
    expect(body.exists).toBe(true);
    expect(body.name).toBe(uploadName);
  });

  it("succeeds when uploading duplicate with overwrite=true", async () => {
    const content = await loadTestSafe("simple.psafe3");
    const resp = await api.uploadStaticSafe(uploadName, content, true);

    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.success).toBe(true);
  });

  it("deletes the uploaded safe and it disappears from safe list", async () => {
    // Allow general rate limiter to refill after previous requests
    await sleep(500);

    // Find the safe ID for the uploaded file
    const safes = await api.listSafes();
    const uploaded = safes.find((s) => s.name === uploadName);
    expect(uploaded).toBeDefined();

    const resp = await api.deleteStaticSafe(uploaded!.id);

    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.success).toBe(true);

    const safesAfter = await api.listSafes();
    const names = safesAfter.map((s) => s.name);
    expect(names).not.toContain(uploadName);
  });

  it("returns error when deleting a non-existent safe", async () => {
    await sleep(500);
    const resp = await api.deleteStaticSafe("0000000000000000");

    expect(resp.status).toBe(404);
    const body = await resp.json();
    expect(body.error).toBeTruthy();
  });
});
