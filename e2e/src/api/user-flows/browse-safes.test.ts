import { it, expect } from "vitest";
import { describeDualMode } from "../../helpers/dual-mode";

describeDualMode("Browse safes and providers", {}, (getApi) => {
  it("lists all safes from the static provider", async () => {
    const api = getApi();
    const safes = await api.listSafes();

    expect(safes).toBeInstanceOf(Array);
    expect(safes.length).toBeGreaterThanOrEqual(2);

    const names = safes.map((s) => s.name);
    expect(names).toContain("simple.psafe3");
    expect(names).toContain("three.psafe3");
  });

  it("each safe has the expected fields", async () => {
    const api = getApi();
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
    const api = getApi();
    const safes = await api.listSafes();
    for (const safe of safes) {
      expect(safe.provider).toBe("static");
    }
  });

  it("lists available providers including mock", async () => {
    const api = getApi();
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
