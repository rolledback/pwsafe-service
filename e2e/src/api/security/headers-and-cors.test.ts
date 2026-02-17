import { it, expect } from "vitest";
import { describeDualMode } from "../../helpers/dual-mode";

describeDualMode("Headers and CORS", {}, (getApi) => {
  it("API response does NOT contain Access-Control-Allow-Origin", async () => {
    const api = getApi();
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("response contains X-Content-Type-Options: nosniff", async () => {
    const api = getApi();
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("response contains X-Frame-Options: DENY", async () => {
    const api = getApi();
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.headers.get("x-frame-options")).toBe("DENY");
  });

  it("response contains Referrer-Policy: no-referrer", async () => {
    const api = getApi();
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("GET /web/ contains Content-Security-Policy with CSP nonce (not unsafe-inline)", async () => {
    const api = getApi();
    const resp = await api.raw("GET", "/web/", { csrfToken: null });
    const csp = resp.headers.get("content-security-policy");
    expect(csp).toBeTruthy();
    expect(csp).toContain("'nonce-");
    // Verify script-src uses nonce, not unsafe-inline
    const scriptSrc = csp!.split(";").find((d: string) => d.trim().startsWith("script-src"));
    expect(scriptSrc).toBeTruthy();
    expect(scriptSrc).not.toContain("'unsafe-inline'");
  });

  it("successive /web/ requests have different CSP nonces", async () => {
    const api = getApi();
    const resp1 = await api.raw("GET", "/web/", { csrfToken: null });
    const resp2 = await api.raw("GET", "/web/", { csrfToken: null });

    const csp1 = resp1.headers.get("content-security-policy")!;
    const csp2 = resp2.headers.get("content-security-policy")!;

    const cspNonceRegex = /'nonce-([^']+)'/;
    const cspNonce1 = csp1.match(cspNonceRegex)?.[1];
    const cspNonce2 = csp2.match(cspNonceRegex)?.[1];

    expect(cspNonce1).toBeTruthy();
    expect(cspNonce2).toBeTruthy();
    expect(cspNonce1).not.toBe(cspNonce2);
  });

  it("API responses include Cache-Control: no-store", async () => {
    const api = getApi();
    const resp = await api.raw("GET", "/api/safes");
    expect(resp.headers.get("cache-control")).toBe("no-store");
  });

  it("/web/ responses do NOT include Cache-Control: no-store", async () => {
    const api = getApi();
    const resp = await api.raw("GET", "/web/", { csrfToken: null });
    expect(resp.headers.get("cache-control")).not.toBe("no-store");
  });

  it("/web/bundle.js.map returns 404", async () => {
    const api = getApi();
    const resp = await api.raw("GET", "/web/bundle.js.map", { csrfToken: null });
    expect(resp.status).toBe(404);
  });

  it("security headers present on error responses", async () => {
    const api = getApi();
    const resp = await api.raw("GET", "/api/nonexistent");
    expect(resp.headers.get("x-content-type-options")).toBe("nosniff");
    expect(resp.headers.get("x-frame-options")).toBe("DENY");
    expect(resp.headers.get("referrer-policy")).toBe("no-referrer");
  });
});
