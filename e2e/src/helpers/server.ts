import { spawn, ChildProcess } from "node:child_process";
import { mkdtemp, cp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const PROJECT_ROOT = resolve(import.meta.dirname, "..", "..", "..");
const BACKEND_DIR = join(PROJECT_ROOT, "backend");
const TESTDATA_DIR = join(BACKEND_DIR, "testdata");
const FRONTEND_DIST = join(PROJECT_ROOT, "frontend", "dist");
const BINARY_NAME = process.platform === "win32" ? "pwsafe-service.exe" : "pwsafe-service";

export interface RateLimitTierOptions {
  rate: number;
  burst: number;
}

export interface ServerOptions {
  syncInterval?: string; // e.g., "3s", "15m"
  authMode?: "disabled" | "enabled";
  password?: string;
  sessionTimeout?: string; // e.g., "2s", "3m"
  skipAuthSetup?: boolean; // skip auto-setup (for auth-setup tests)
  trustedProxies?: string[]; // IPs allowed to set proxy headers
  rateLimiter?: {
    standard?: RateLimitTierOptions;
    strict?: RateLimitTierOptions;
    web?: RateLimitTierOptions;
  };
}

export class ServerInstance {
  private process: ChildProcess | null = null;
  private tempDir: string = "";
  private options: ServerOptions;

  public baseUrl: string = "";
  public csrfToken: string = "";
  public port: number = 0;
  public configDir: string = "";

  constructor(options: ServerOptions = {}) {
    this.options = options;
  }

  async start(): Promise<void> {
    this.tempDir = await mkdtemp(join(tmpdir(), "pwsafe-e2e-"));

    const configDir = join(this.tempDir, "config");
    this.configDir = configDir;
    const dataDir = join(this.tempDir, "data");
    const staticDir = join(this.tempDir, "static");
    const staticDataDir = join(dataDir, "static");

    await mkdir(configDir, { recursive: true });
    await mkdir(staticDataDir, { recursive: true });

    // Copy test fixtures into data/static/
    await cp(TESTDATA_DIR, staticDataDir, { recursive: true });

    // Copy built frontend
    await cp(FRONTEND_DIST, staticDir, { recursive: true });

    const binaryPath = join(BACKEND_DIR, BINARY_NAME);

    // Find a free port before starting so we can set baseUrl in settings
    const port = await this.findFreePort();
    this.port = port;
    this.baseUrl = `http://127.0.0.1:${port}`;

    // Write settings.json with mock provider enabled and correct base URL
    const settings: Record<string, unknown> = {
      baseUrl: this.baseUrl,
      providers: {
        mock: {},
      },
    };
    if (this.options.syncInterval) {
      settings.syncInterval = this.options.syncInterval;
    }
    if (this.options.sessionTimeout) {
      settings.auth = { sessionTimeout: this.options.sessionTimeout };
    }
    if (this.options.rateLimiter) {
      settings.rateLimiter = this.options.rateLimiter;
    }
    if (this.options.trustedProxies) {
      settings.trustedProxies = this.options.trustedProxies;
    }
    await writeFile(join(configDir, "settings.json"), JSON.stringify(settings, null, 2));

    this.process = spawn(binaryPath, [], {
      cwd: BACKEND_DIR,
      env: {
        ...process.env,
        PWSAFE_CONFIG_DIR: configDir,
        PWSAFE_DATA_DIR: dataDir,
        PWSAFE_STATIC_DIR: staticDir,
        PWSAFE_PORT: String(port),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    // Wait for server to be ready
    await this.waitForReady();

    // Extract CSRF token from served HTML
    await this.extractCsrfToken();

    // Setup auth mode (default to "disabled" so existing tests keep working)
    if (!this.options.skipAuthSetup) {
      const mode = this.options.authMode ?? "disabled";
      const setupBody: Record<string, string> = { mode };
      if (mode === "enabled" && this.options.password) {
        setupBody.password = this.options.password;
      }
      const setupResp = await fetch(`${this.baseUrl}/api/auth/setup`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-PWSAFE-CSRF-Token": this.csrfToken },
        body: JSON.stringify(setupBody),
      });
      if (!setupResp.ok) throw new Error(`Auth setup failed: ${await setupResp.text()}`);
    }
  }

  async stop(): Promise<void> {
    if (this.process) {
      // Send SIGTERM for graceful shutdown (flushes coverage data)
      this.process.kill("SIGTERM");
      // Wait briefly for process to exit
      await new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          this.process?.kill("SIGKILL");
          resolve();
        }, 3000);
        this.process!.on("exit", () => {
          clearTimeout(timeout);
          resolve();
        });
      });
      this.process = null;
    }
    if (this.tempDir) {
      try {
        await rm(this.tempDir, { recursive: true, force: true });
      } catch {
        // Best effort cleanup
      }
    }
  }

  private async findFreePort(): Promise<number> {
    const { createServer } = await import("node:net");
    return new Promise((resolve, reject) => {
      const server = createServer();
      server.listen(0, () => {
        const addr = server.address();
        if (addr && typeof addr === "object") {
          const port = addr.port;
          server.close(() => resolve(port));
        } else {
          reject(new Error("Failed to get port"));
        }
      });
    });
  }

  private async waitForReady(timeoutMs = 10000): Promise<void> {
    const start = Date.now();
    const interval = 100;

    while (Date.now() - start < timeoutMs) {
      try {
        const resp = await fetch(`${this.baseUrl}/web/`);
        if (resp.ok) return;
      } catch {
        // Server not ready yet
      }
      await new Promise((r) => setTimeout(r, interval));
    }
    throw new Error(`Server failed to become ready within ${timeoutMs}ms at ${this.baseUrl}`);
  }

  private async extractCsrfToken(): Promise<void> {
    const resp = await fetch(`${this.baseUrl}/web/`);
    const html = await resp.text();
    const match = html.match(/window\.__PWSAFE_CSRF_TOKEN="([a-f0-9]+)"/);
    if (!match) {
      throw new Error("Failed to extract CSRF token from served HTML");
    }
    this.csrfToken = match[1];
  }
}
