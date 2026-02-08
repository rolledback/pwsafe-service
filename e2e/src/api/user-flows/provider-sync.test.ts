import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

describe("Provider sync behavior", { timeout: 60_000 }, () => {
  let server: ServerInstance;
  let api: ApiClient;

  beforeAll(async () => {
    server = new ServerInstance({ syncInterval: "3s" });
    await server.start();
    api = new ApiClient(server.baseUrl, server.apiToken);

    // Connect the mock provider
    const { url } = await api.getProviderAuthUrl("mock");
    await api.raw("GET", url.replace(server.baseUrl, ""));
  });

  afterAll(async () => {
    await server.stop();
  });

  it("syncs selected files and they appear in safe list", async () => {
    // Get available files from mock provider
    const { files } = await api.getProviderFiles("mock");
    expect(files.length).toBeGreaterThanOrEqual(2);

    // Select all files
    const selected = files.map((f) => ({ ...f, selected: true }));
    await api.saveProviderFiles("mock", selected);

    // Trigger manual sync
    const syncResult = await api.syncProvider("mock");
    expect(syncResult.results.length).toBeGreaterThan(0);
    for (const r of syncResult.results) {
      expect(r.success).toBe(true);
    }

    // Verify synced files appear in safe list
    const safes = await api.listSafes();
    const mockSafes = safes.filter((s) => s.provider === "mock");
    expect(mockSafes.length).toBe(files.length);
  });

  it("deselecting files and syncing removes them", async () => {
    // Get current files
    const { files } = await api.getProviderFiles("mock");

    // Deselect all files
    const deselected = files.map((f) => ({ ...f, selected: false }));
    await api.saveProviderFiles("mock", deselected);

    // Sync to clean up
    await api.syncProvider("mock");

    // Verify mock files are gone from safe list
    const safes = await api.listSafes();
    const mockSafes = safes.filter((s) => s.provider === "mock");
    expect(mockSafes.length).toBe(0);
  });

  it("re-select and verify periodic sync picks up files automatically", async () => {
    // Select files again
    const { files } = await api.getProviderFiles("mock");
    const selected = files.map((f) => ({ ...f, selected: true }));
    await api.saveProviderFiles("mock", selected);

    // Do NOT manually sync — wait for periodic sync (3s interval + buffer)
    await new Promise((r) => setTimeout(r, 5000));

    // Verify files appeared via periodic sync
    const safes = await api.listSafes();
    const mockSafes = safes.filter((s) => s.provider === "mock");
    expect(mockSafes.length).toBeGreaterThan(0);
  });

  it("syncs only selected files when mix of selected/unselected", async () => {
    const { files } = await api.getProviderFiles("mock");
    expect(files.length).toBeGreaterThanOrEqual(2);

    // Select only the first file
    const mixed = files.map((f, i) => ({ ...f, selected: i === 0 }));
    await api.saveProviderFiles("mock", mixed);

    // Sync
    const syncResult = await api.syncProvider("mock");
    const successful = syncResult.results.filter((r) => r.success);
    expect(successful.length).toBe(1);

    // Verify only one mock safe in list
    const safes = await api.listSafes();
    const mockSafes = safes.filter((s) => s.provider === "mock");
    expect(mockSafes.length).toBe(1);
  });
});
