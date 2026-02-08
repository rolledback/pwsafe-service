import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

describe("Mock provider lifecycle", { timeout: 60_000 }, () => {
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

  it("starts disconnected", async () => {
    const status = await api.getProviderStatus("mock");
    expect(status.connected).toBe(false);
  });

  it("returns an auth URL", async () => {
    const { url } = await api.getProviderAuthUrl("mock");
    expect(url).toBeTruthy();
    expect(url).toContain("code=mock-auth-code");
  });

  it("auth callback returns a redirect", async () => {
    const { url } = await api.getProviderAuthUrl("mock");

    // The mock auth URL already points to the callback endpoint
    const resp = await api.raw("GET", url.replace(server.baseUrl, ""));

    expect(resp.status).toBe(302);
  });

  it("is connected after auth callback", async () => {
    const status = await api.getProviderStatus("mock");
    expect(status.connected).toBe(true);
  });

  it("lists remote files from testdata", async () => {
    const { files } = await api.getProviderFiles("mock");

    expect(files).toBeInstanceOf(Array);
    expect(files.length).toBeGreaterThanOrEqual(2);

    const names = files.map((f) => f.name);
    expect(names).toContain("simple.psafe3");
    expect(names).toContain("three.psafe3");
  });

  it("saves selected files", async () => {
    const { files } = await api.getProviderFiles("mock");

    const selected = files.map((f) => ({ ...f, selected: true }));
    const result = await api.saveProviderFiles("mock", selected);
    expect(result.success).toBe(true);
  });

  it("syncs files successfully", async () => {
    const { results } = await api.syncProvider("mock");

    expect(results).toBeInstanceOf(Array);
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      expect(r.success).toBe(true);
      expect(r.name).toBeTruthy();
    }
  });

  it("synced files appear in /api/safes", async () => {
    const safes = await api.listSafes();
    const mockSafes = safes.filter((s) => s.provider === "mock");

    expect(mockSafes.length).toBeGreaterThan(0);

    const names = mockSafes.map((s) => s.name);
    expect(names).toContain("simple.psafe3");
    expect(names).toContain("three.psafe3");
  });

  it("disconnects successfully", async () => {
    const result = await api.disconnectProvider("mock");
    expect(result.success).toBe(true);
  });

  it("is disconnected after disconnect", async () => {
    const status = await api.getProviderStatus("mock");
    expect(status.connected).toBe(false);
  });
});
