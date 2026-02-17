import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

describe("Rate Limiting", () => {
  let server: ServerInstance;
  let api: ApiClient;

  beforeAll(async () => {
    server = new ServerInstance();
    await server.start();
    api = new ApiClient(server.baseUrl, server.csrfToken);
    // Wait for strict rate limiter to refill after auth setup call during start
    await new Promise((r) => setTimeout(r, 5500));
  });

  afterAll(async () => {
    await server.stop();
  });

  it(
    "unlock endpoint rate limits after burst allowance (0.2 req/s, burst 2)",
    async () => {
      const safes = await api.listSafes();
      const safeId = safes.length > 0 ? safes[0].id : "nonexistent";
      const path = `/api/safes/${safeId}/unlock`;

      const statuses: number[] = [];

      // Send 5 rapid requests — burst of 2 should pass, rest should be limited
      for (let i = 0; i < 5; i++) {
        const resp = await api.raw("POST", path, {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: "wrongpassword" }),
        });
        statuses.push(resp.status);
      }

      // First 2 requests should be allowed (burst), not rate-limited
      expect(statuses[0]).not.toBe(429);
      expect(statuses[1]).not.toBe(429);

      // At least one subsequent request should be rate limited
      expect(statuses.slice(2)).toContain(429);

      // Majority of post-burst requests should be blocked
      const blocked = statuses.slice(2).filter((s) => s === 429).length;
      expect(blocked).toBeGreaterThanOrEqual(2);
    },
    { timeout: 15000 },
  );

  it("spoofed X-Forwarded-For does NOT bypass rate limiting", async () => {
    // Wait for rate limiter to refill
    await new Promise((r) => setTimeout(r, 5500));

    const safes = await api.listSafes();
    const safeId = safes.length > 0 ? safes[0].id : "nonexistent";
    const path = `/api/safes/${safeId}/unlock`;

    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const resp = await api.raw("POST", path, {
        headers: {
          "Content-Type": "application/json",
          "X-Forwarded-For": `10.0.0.${i}`,
        },
        body: JSON.stringify({ password: "wrong" }),
      });
      statuses.push(resp.status);
    }

    // Should still be rate limited despite spoofed XFF — no trusted proxies
    // configured, so real IP (127.0.0.1) is used for all requests
    expect(statuses.slice(2)).toContain(429);
  }, 15000);
});

describe("Web Rate Limiting", () => {
  let server: ServerInstance;

  beforeAll(async () => {
    server = new ServerInstance();
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  it(
    "/web/ rate limits after burst allowance",
    async () => {
      // Default web tier: 50 req/s, burst 50. Fire 60 parallel requests to exhaust burst.
      const responses = await Promise.all(Array.from({ length: 60 }, () => fetch(`${server.baseUrl}/web/`)));
      const statuses = responses.map((r) => r.status);

      // Early requests should succeed
      expect(statuses[0]).toBe(200);

      // At least one request should be rate limited
      expect(statuses).toContain(429);

      // Multiple post-burst requests should be blocked
      const blocked = statuses.filter((s) => s === 429).length;
      expect(blocked).toBeGreaterThanOrEqual(3);
    },
    { timeout: 15000 },
  );
});
