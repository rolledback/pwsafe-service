import { it, expect } from "vitest";
import { describeDualMode } from "../../helpers/dual-mode";
import type { SafeFile } from "../../../../frontend/src/api/client";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// The strict rate limiter allows burst of 2 at 0.2 req/s.
// After the burst is consumed, wait for a token to refill.
const STRICT_RATE_WAIT = 5500;

describeDualMode("Safe access user journey", {}, (getApi) => {
  let simpleSafe: SafeFile;
  let threeSafe: SafeFile;

  it("find test safes", async () => {
    const api = getApi();
    const safes = await api.listSafes();
    simpleSafe = safes.find((s) => s.name === "simple.psafe3")!;
    threeSafe = safes.find((s) => s.name === "three.psafe3")!;
    expect(simpleSafe).toBeDefined();
    expect(threeSafe).toBeDefined();
  });

  it("unlocks simple.psafe3 with correct password", async () => {
    const api = getApi();
    // Wait for strict rate limiter to refill after auth setup/login during server start
    await sleep(STRICT_RATE_WAIT);
    const { status, body } = await api.unlockSafe(simpleSafe.id, "password");

    expect(status).toBe(200);
    expect("groups" in body).toBe(true);
    expect("entries" in body).toBe(true);

    const structure = body as { groups: any[]; entries: any[] };
    expect(structure.groups.length).toBeGreaterThanOrEqual(1);

    const testGroup = structure.groups.find((g) => g.name === "test");
    expect(testGroup).toBeDefined();
    expect(testGroup.entries.length).toBe(1);
    expect(testGroup.entries[0].title).toBe("Test entry");
    expect(testGroup.entries[0].username).toBe("test");
    expect(testGroup.entries[0].uuid).toBe("c4dcfb52-b944-f141-af96-b746f184afe2");
  });

  it("unlocks three.psafe3 and verifies multi-group structure", async () => {
    const api = getApi();
    await sleep(STRICT_RATE_WAIT);
    const { status, body } = await api.unlockSafe(threeSafe.id, "three3#;");

    expect(status).toBe(200);
    const structure = body as { groups: any[]; entries: any[] };
    expect(structure.groups.length).toBeGreaterThanOrEqual(3);

    const groupNames = structure.groups.map((g: any) => g.name);
    expect(groupNames).toContain("group1");
    expect(groupNames).toContain("group2");
    expect(groupNames).toContain("group 3");
  });

  it("retrieves entry password for a known entry", async () => {
    const api = getApi();
    await sleep(STRICT_RATE_WAIT);
    const entryUuid = "c4dcfb52-b944-f141-af96-b746f184afe2";

    const { status, body } = await api.getEntryPassword(simpleSafe.id, "password", entryUuid);

    expect(status).toBe(200);
    expect("password" in body).toBe(true);
    expect((body as { password: string }).password).toBe("password");
  });

  it("returns error for wrong password", async () => {
    const api = getApi();
    await sleep(STRICT_RATE_WAIT);
    const { status, body } = await api.unlockSafe(simpleSafe.id, "wrong-password");

    expect(status).not.toBe(200);
    expect("error" in body).toBe(true);
  });

  it("returns 404 for non-existent safe ID", async () => {
    const api = getApi();
    await sleep(STRICT_RATE_WAIT);
    const { status, body } = await api.unlockSafe("non-existent-safe-id", "password");

    expect(status).toBe(404);
    expect("error" in body).toBe(true);
  });

  it("returns error for wrong entry UUID", async () => {
    const api = getApi();
    await sleep(STRICT_RATE_WAIT);
    const { status, body } = await api.getEntryPassword(simpleSafe.id, "password", "00000000-0000-0000-0000-000000000000");

    expect(status).not.toBe(200);
    expect("error" in body).toBe(true);
  });
});
