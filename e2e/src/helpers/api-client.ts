import type {
  SafeFile,
  SafeStructure,
  ProvidersResponse,
  ProviderStatus,
  ProviderFilesResponse,
  ProviderSyncResponse,
  ProviderFile,
} from "../../../frontend/src/api/client";

export class ApiClient {
  private cookies: Record<string, string> = {};

  constructor(
    private baseUrl: string,
    private csrfToken: string,
  ) {}

  async login(password: string): Promise<void> {
    const resp = await this.raw("POST", "/api/auth/login", {
      body: JSON.stringify({ password }),
      headers: { "Content-Type": "application/json" },
    });
    if (resp.status !== 200) throw new Error(`Login failed: ${resp.status}`);
    const setCookie = resp.headers.get("set-cookie");
    if (setCookie) {
      const match = setCookie.match(/pwsafe_session_id=([^;]+)/);
      if (match) this.cookies["pwsafe_session_id"] = match[1];
    }
  }

  async logout(): Promise<void> {
    await this.raw("POST", "/api/auth/logout");
    delete this.cookies["pwsafe_session_id"];
  }

  // Raw request — returns full Response for status/header inspection
  async raw(
    method: string,
    path: string,
    options: {
      body?: string | FormData;
      headers?: Record<string, string>;
      csrfToken?: string | null; // null = omit CSRF token, undefined = use default
    } = {},
  ): Promise<Response> {
    const headers: Record<string, string> = { ...options.headers };

    if (options.csrfToken !== null) {
      headers["X-PWSAFE-CSRF-Token"] = options.csrfToken ?? this.csrfToken;
    }

    if (Object.keys(this.cookies).length > 0) {
      const cookieStr = Object.entries(this.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");
      headers["Cookie"] = cookieStr;
    }

    return fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: options.body,
      redirect: "manual",
    });
  }

  // Typed convenience methods

  async listSafes(): Promise<SafeFile[]> {
    const resp = await this.raw("GET", "/api/safes");
    return resp.json();
  }

  async unlockSafe(id: string, password: string): Promise<{ status: number; body: SafeStructure | { error: string } }> {
    const resp = await this.raw("POST", `/api/safes/${id}/unlock`, {
      body: JSON.stringify({ password }),
      headers: { "Content-Type": "application/json" },
    });
    return { status: resp.status, body: await resp.json() };
  }

  async getEntryPassword(
    id: string,
    password: string,
    entryUuid: string,
  ): Promise<{ status: number; body: { password: string } | { error: string } }> {
    const resp = await this.raw("POST", `/api/safes/${id}/entry`, {
      body: JSON.stringify({ password, entryUuid }),
      headers: { "Content-Type": "application/json" },
    });
    return { status: resp.status, body: await resp.json() };
  }

  async listProviders(): Promise<ProvidersResponse> {
    const resp = await this.raw("GET", "/api/providers");
    return resp.json();
  }

  async getProviderStatus(providerId: string): Promise<ProviderStatus> {
    const resp = await this.raw("GET", `/api/providers/${providerId}/status`);
    return resp.json();
  }

  async getProviderFiles(providerId: string): Promise<ProviderFilesResponse> {
    const resp = await this.raw("GET", `/api/providers/${providerId}/files`);
    return resp.json();
  }

  async saveProviderFiles(providerId: string, files: ProviderFile[]): Promise<{ success: boolean }> {
    const resp = await this.raw("PUT", `/api/providers/${providerId}/files`, {
      body: JSON.stringify({ files }),
      headers: { "Content-Type": "application/json" },
    });
    return resp.json();
  }

  async syncProvider(providerId: string): Promise<ProviderSyncResponse> {
    const resp = await this.raw("POST", `/api/providers/${providerId}/sync`);
    return resp.json();
  }

  async getProviderAuthUrl(providerId: string): Promise<{ url: string }> {
    const resp = await this.raw("GET", `/api/providers/${providerId}/auth/url`);
    return resp.json();
  }

  async disconnectProvider(providerId: string): Promise<{ success: boolean }> {
    const resp = await this.raw("POST", `/api/providers/${providerId}/disconnect`);
    return resp.json();
  }

  async uploadStaticSafe(filename: string, content: Uint8Array, overwrite = false): Promise<Response> {
    const form = new FormData();
    form.append("file", new Blob([new Uint8Array(content)]), filename);
    const path = overwrite ? "/api/providers/static/files?overwrite=true" : "/api/providers/static/files";
    return this.raw("POST", path, { body: form as any });
  }

  async deleteStaticSafe(id: string): Promise<Response> {
    return this.raw("DELETE", `/api/providers/static/files/${id}`);
  }

  async getAuthStatus(): Promise<{ mode: string; authenticated: boolean }> {
    const resp = await this.raw("GET", "/api/auth/status");
    return resp.json();
  }

  async authSetup(mode: string, password?: string): Promise<{ status: string }> {
    const body: Record<string, string> = { mode };
    if (password) body.password = password;
    const resp = await this.raw("POST", "/api/auth/setup", {
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    });
    return resp.json();
  }
}
