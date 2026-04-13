import { it, expect } from "vitest";
import { describeDualMode } from "../../helpers/dual-mode";

describeDualMode("Upload Validation", {}, (getApi) => {
  it("rejects upload with .txt extension", async () => {
    const api = getApi();
    const content = Buffer.from("fake content");
    const resp = await api.uploadStaticSafe("test.txt", content);
    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toContain(".psafe3");
  });

  it("accepts upload with .psafe3 extension", async () => {
    const api = getApi();
    const content = Buffer.from("fake psafe3 content");
    const resp = await api.uploadStaticSafe("test-upload.psafe3", content);
    // Should succeed (200) or conflict (409 if already exists)
    expect([200, 409]).toContain(resp.status);
  });

  it("rejects upload with no extension", async () => {
    const api = getApi();
    const content = Buffer.from("fake content");
    const resp = await api.uploadStaticSafe("noextension", content);
    expect(resp.status).toBe(400);
  });

  it("rejects upload with .psafe3.txt double extension", async () => {
    const api = getApi();
    const content = Buffer.from("fake content");
    const resp = await api.uploadStaticSafe("test.psafe3.txt", content);
    expect(resp.status).toBe(400);
  });

  it("rejects oversized file upload", async () => {
    const api = getApi();
    // Create a buffer slightly over 10MB (default maxSafeFileSize)
    const oversizedContent = Buffer.alloc(11 * 1024 * 1024, 0x41);
    const resp = await api.uploadStaticSafe("oversized.psafe3", oversizedContent);
    expect(resp.status).toBe(413);
  });
});
