import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { ServerInstance } from "../../helpers/server";
import { ApiClient } from "../../helpers/api-client";

describe("Rate Limiting", () => {
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
    },
    { timeout: 15000 },
  );
});
