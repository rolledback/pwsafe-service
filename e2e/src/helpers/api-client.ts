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
  constructor(
    private baseUrl: string,
    private token: string,
  ) {}

  // Raw request — returns full Response for status/header inspection
  async raw(
    method: string,
    path: string,
    options: {
      body?: string | FormData;
      headers?: Record<string, string>;
      token?: string | null; // null = omit token, undefined = use default
    } = {},
  ): Promise<Response> {
    const headers: Record<string, string> = { ...options.headers };

    if (options.token !== null) {
      headers["X-PWSAFE-Token"] = options.token ?? this.token;
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

  async deleteStaticSafe(filename: string): Promise<Response> {
    return this.raw("DELETE", `/api/providers/static/files/${encodeURIComponent(filename)}`);
  }
}
