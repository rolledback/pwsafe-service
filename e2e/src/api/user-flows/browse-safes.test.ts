import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

describe("Browse safes and providers", () => {
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

  it("lists all safes from the static provider", async () => {
    const safes = await api.listSafes();

    expect(safes).toBeInstanceOf(Array);
    expect(safes.length).toBeGreaterThanOrEqual(2);

    const names = safes.map((s) => s.name);
    expect(names).toContain("simple.psafe3");
    expect(names).toContain("three.psafe3");
  });

  it("each safe has the expected fields", async () => {
    const safes = await api.listSafes();

    for (const safe of safes) {
      expect(safe.id).toBeTruthy();
      expect(safe.name).toBeTruthy();
      expect(safe.path).toBeTruthy();
      expect(safe.lastModified).toBeTruthy();
      expect(safe.provider).toBeTruthy();
    }
  });

  it("all safes belong to the static provider", async () => {
    const safes = await api.listSafes();
    for (const safe of safes) {
      expect(safe.provider).toBe("static");
    }
  });

  it("lists available providers including mock", async () => {
    const { providers } = await api.listProviders();

    expect(providers).toBeInstanceOf(Array);
    expect(providers.length).toBeGreaterThanOrEqual(1);

    const mock = providers.find((p) => p.id === "mock");
    expect(mock).toBeDefined();
    expect(mock!.displayName).toBeTruthy();
    expect(mock!.icon).toBeTruthy();
    expect(mock!.brandColor).toBeTruthy();
  });
});
